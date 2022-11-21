#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <errno.h>
#include <unistd.h> //F_OK
#include <linux/if_link.h> //XDP_FLAGS_HW_MODE
#include <linux/bpf.h>
#include <arpa/inet.h> // sockaddr_in
#include "kafkaprobe.h"

void set_native_mode(__u32 *flag)
{
	*flag = XDP_FLAGS_UPDATE_IF_NOEXIST;
    *flag &= ~XDP_FLAGS_MODES;    /* Clear flags */
    *flag |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
}

void set_socket_mode(__u32 *flag)
{
	*flag = XDP_FLAGS_UPDATE_IF_NOEXIST;
    *flag &= ~XDP_FLAGS_MODES;    /* Clear flags */
    *flag |= XDP_FLAGS_SKB_MODE;  /* Set   flag */	
}

void set_offload_mode(__u32 *flag)
{
	*flag = XDP_FLAGS_UPDATE_IF_NOEXIST;
    *flag &= ~XDP_FLAGS_MODES;    /* Clear flags */
    *flag |= XDP_FLAGS_HW_MODE;  /* Set   flag */		
}


struct bpf_object *load(struct KafkaConfig *cfg){
    struct bpf_object *obj;

    struct bpf_prog_load_attr load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex = 0,
        .file = cfg->load_file_name,
    };

    if (cfg->xdp_flag & XDP_FLAGS_HW_MODE)
		load_attr.ifindex = cfg->ifindex;

    int ret;
    int first_prog_fd = -1;

    ret = bpf_prog_load_xattr(&load_attr, &obj, &first_prog_fd);
	if (ret) {
		fprintf(stderr, "ERROR: loading BPF-OBJ file %s fail\n",cfg->load_file_name);
		return NULL;
	}    

    return obj;
}

int unload(struct bpf_object *obj){
    int ret;

    ret = bpf_object__unload(obj);
    if (ret){
		fprintf(stderr, "ERROR: unloading BPF-OBJ file fail\n");
		return 1;        
    }

    return 0;
}

int link_xdp(struct KafkaConfig *cfg, struct bpf_object *obj){

    struct bpf_program *prog;
    int prog_fd = -1;
    int ret;

    prog = bpf_program__next(NULL, obj);
    if(!prog){
		fprintf(stderr, "ERROR: can't find prog in bpf object\n");
		return 1;             
    }

    prog_fd = bpf_program__fd(prog);

    ret = bpf_set_link_xdp_fd(cfg->ifindex, prog_fd, cfg->xdp_flag);
    if(ret){
        switch(ret){
            case -EBUSY:
                fprintf(stderr, "Warn: net interface %s already loaded XDP prog\n", cfg->ifname);     
                break;
            case -EOPNOTSUPP:
                fprintf(stderr, "Warn: net interface %s not support flag 0x%x\n", cfg->ifname, cfg->xdp_flag);     
                break;               
            default:
                fprintf(stderr, "ERROR: net interface %s link prog %s fail\n",cfg->ifname, cfg->load_file_name);
                break;
        }     
        return ret;   
    }    

    return 0;
}

int unlink_xdp(struct KafkaConfig *cfg){
    int ret;
    __u32 prog_fd;

	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_fd, cfg->xdp_flag);
	if (ret) {
		fprintf(stderr, "ERR: get link xdp prog fd failed \n");
		return 1;
	}

	if (!prog_fd) {
        printf("INFO: ifname %s has no XDP prog\n", cfg->ifname);
		return 0;
	}

    ret = bpf_set_link_xdp_fd(cfg->ifindex, -1, cfg->xdp_flag);
	if (ret < 0) {
		fprintf(stderr, "ERROR: unlink xdp prog from net interface %s fail\n", cfg->ifname);
		return 3;
	}

	return 0;
}

int unpin(struct KafkaConfig *cfg, struct bpf_object *obj){
    int ret;

    char dir_path[LARGE_BUF_SIZE];
    snprintf(dir_path, LARGE_BUF_SIZE, "%s/%s", cfg->pin_path, cfg->ifname);   

    ret = bpf_object__unpin_maps(obj, dir_path);
    if(ret){
        fprintf(stderr, "ERROR: can't remove map!\n");
        return 1;
    }    

    return 0;
}

int pin(struct KafkaConfig *cfg, struct bpf_object *obj){
    int ret;
    char map_path[LARGE_BUF_SIZE];
    char dir_path[LARGE_BUF_SIZE];
    snprintf(dir_path, LARGE_BUF_SIZE, "%s/%s", cfg->pin_path, cfg->ifname);   
    for(int i=0;i<MAP_NUM;i++){            
        snprintf(map_path, LARGE_BUF_SIZE, "%s/%s/%s",cfg->pin_path, cfg->ifname, get_map_name(i));

        ret = access(map_path, F_OK);
        if(ret != -1){
            unpin(cfg, obj);
            break;
        }
    }

    ret = bpf_object__pin_maps(obj, dir_path);
    if(ret){
        fprintf(stderr, "ERROR: can't pin map in %s\n", dir_path);
        return 1;            
    }

	return 0;    
}

struct bpf_object *load_link_pin(struct KafkaConfig *cfg){

    int ret;
    struct bpf_object *obj;

    obj = load(cfg);
    if(!obj){
        fprintf(stderr, "ERROR: can't load bpf object!\n");
        return NULL;            
    }

    ret = link_xdp(cfg, obj);

    if (ret == -EBUSY) {
        char replication[4];
        printf("Do you want to unlink the XDP prog which is runing? please input 'y' or 'n':\n");
        scanf("%s", replication);
        if (replication[0] == 'y') {
            unlink_xdp(cfg);
            ret = link_xdp(cfg, obj);
        } else {
            return NULL;
        }
    }    
    
    if (ret == -EOPNOTSUPP) {
        printf("Info: Change XDP mode to socket mode...\n");
        set_socket_mode(&cfg->xdp_flag);
        ret = link_xdp(cfg, obj);
    }
    
    if(ret){
        fprintf(stderr, "ERROR %d: can't link bpf prog!, \n", ret);
        return NULL;            
    }    

    ret = pin(cfg, obj);
    if(ret){
        fprintf(stderr, "ERROR: can't pin bpf map!\n");
        return NULL;            
    }   

    return obj;
}

int unpin_unlink_unload(struct KafkaConfig *cfg, struct bpf_object *obj){
    int ret;
    ret = unpin(cfg, obj);
    if(ret){
        fprintf(stderr, "ERROR: unpin bpf map fail!\n");
        return 1;            
    }       

    ret = unlink_xdp(cfg);
    if(ret){
        fprintf(stderr, "ERROR: unlink bpf prog fail!\n");
        return 1;            
    }   

    ret = unload(obj);
    if(ret){
        fprintf(stderr, "ERROR: unload bpf object fail!\n");
        return 1;            
    }        

    return 0;
}

int open_bpf_map_file(struct KafkaConfig *cfg, const char *map_name, int *map_fd){
    char map_path[LARGE_BUF_SIZE];
    snprintf(map_path, LARGE_BUF_SIZE, "%s/%s/%s", cfg->pin_path, cfg->ifname, map_name);

    int fd;
    fd = bpf_obj_get(map_path);
    if(fd < 0){
		printf("ERROR: Failed to open bpf map file:%s\n", map_path);
		return 1;       
    }

    *map_fd = fd;
    return 0;
}

static char local_ip[SMALL_BUF_SIZE];

const char* get_local_ip() 
{
    return local_ip;
}

int set_local_ip(char * ifname)
{
    struct ifaddrs *if_addr = 0;
    struct ifaddrs *ifa;
    struct sockaddr_in *addr = 0;
    int ret;
    int family;

    ret = getifaddrs(&if_addr);
    if (ret != 0 || if_addr == NULL) {
        return -1;
    }

    for (ifa = if_addr; ifa != NULL; ifa = ifa->ifa_next) {
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            if (strcmp(ifa->ifa_name, ifname) ==0) {
                addr = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(family, &addr->sin_addr, local_ip, SMALL_BUF_SIZE);
                return 0;
            }
        }  
    }  

    printf("Error: can't find ip address the ifname %s attached!\n", ifname);
    freeifaddrs(if_addr);
    
	return -1;
}