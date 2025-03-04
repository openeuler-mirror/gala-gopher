# 使用 openEuler LTS 作为基础镜像
FROM openeuler/openeuler:20.03-lts

# 安装必要的工具
RUN yum install -y cmake gcc glibc-devel

# 设置工作目录
WORKDIR /app

# 复制项目文件到容器中
COPY . .

# 构建项目
RUN ./build.sh

# 设置默认命令
CMD ["/bin/bash"]
