# A-ops 故障案例演示 demo程序       

### 故障环境说明      

部署方式：K8S POD部署，部署K8S CNI，每个POD有独立IP、NIC。          
业务访问：         
    web启动三个线程，分别与三个后端建链HTTP链接，并行发起HTTP request；           
    backend启动1个HTTP server，收到请求后，hash给下游（backend 或 javaapp），下游回复后，应答上游；          
    java app启动1个HTTP server，收到请求后，向redis与gaussdb发起请求操作，处理完成后，应答上游；       

心跳访问：backend之间通过http访问方式keepalive，连接关系以配置。（加入心跳主要是将拓扑复杂化，加大故障定界难度）。             
端口：web、backends、dataproc、redis、gaussdb 所有应用端口均唯一。         
IP：所有POD均由K8S CNI分配集群内唯一IP，POD重启后IP保持不变化。         


## demo程序需求

### Web            
a) 可以多实例部署；      
b) 启动多个线程（线程数量可配置）；       
c) 每个线程周期性发起HTTP request（周期可配置）；速率有点问题        
d) 每个线程请求的HTTP server地址可配置（IP、端口）；        
e) 每个线程内串行执行create、update、delete操作，先发create和update和delete ；       
f) 发送速率可配置（默认是best-effort模式，比如100QPM，即每分钟发起100次create/update/delete操作序列），update操作频率可配置（默认10%，即每100次create/update/delete操作序列中，只有10%概率触发updae操作）；           

### Backend        
a) 可以多实例部署；   
b) 启动1个HTTP server（侦听端口可配置）；        
c) 收到HTTP request后，随机选择个下游（下游的HTTP URL、IP、端口可配置），向下游发起请求并获得应答后，回复HTTP request；        
d) Backend之间存在HTTP 访问心跳，每个Backend单独启动一个HTTP server用于接收心跳HTTP request，收到后立即回答；      
e) Backend之间的心跳访问关系可配置（IP、Port）；        
f) Backend支持访问dataproc（java app），参考下面URL，首次访问需先获取token（login接口），并且需要周期性刷新token（每分钟）；     
g) Backend 支持批量写盘操作（由配置开关控制），可以使用dd命令进行磁盘I/O写批量操作（比如：dd if=/dev/zero of=/testw.dbf bs=4k count=100000），每次写完需要删除相应的目录。      
h) 如果“批量写盘操作”配置开关已开启，Backend 收到update操作时，新创建一个线程，由该线程执行“批量写盘操作”，执行完成该线程关闭。      
i) Backend 收到create/update/delete操作时，执行仿真I/O业务操作（比如创建1个文件，写入10K byte内容，flush入盘，然后删除），I/O操作完成后，再将create/update/delete分发下游。        
j) “批量写盘操作”配置开关可以在运行过程中，随时开启/关闭 周期性读文件。        

### URL设计

a) 业务访问URL，PUT接口      
i.      /admin-api/system/user/create          
ii.     /admin-api/system/user/delete         
iii.    /admin-api/system/role/update         
b) 心跳访问URL          
i.      /a-ops/keepalive，POST接口               
c) Dataproc（java app）URL，PUT接口         
i.      /admin-api/system/auth/login            
ii.     /admin-api/system/user/create               
iii.    /admin-api/system/user/delete                 
iv.     /admin-api/system/role/update            