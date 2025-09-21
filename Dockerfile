FROM ubuntu:20.04
WORKDIR /zvdetector
# CN: 安装依赖 EN: Install dependencies
RUN apt-get update && apt-get install vim wget sudo libgl1-mesa-glx libegl1-mesa libxrandr2 libxrandr2 libxss1 libxcursor1 libxcomposite1 libasound2 libxi6 libxtst6

# CN: 安装和配置Conda  EN: Install and configure Conda
RUN sudo su && wget "https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda3-latest-Linux-x86_64.sh" -O ~/miniconda.sh  \
    && bash ~/miniconda.sh -b -p $HOME/miniconda && ~/miniconda/bin/conda init $(echo $SHELL | awk -F '/' '{print $NF}')

RUN echo 'export PATH=/root/miniconda/bin/conda:$PATH' >> ~/.bashrc && source ~/.bashrc && rm -rf miniconda.sh

# CN: 搭建conda fuzzing环境 EN: Build conda fuzzing environment
COPY environment.yml .
RUN conda env create -f environment.yml

# CN: 安装Java 和 Neo4j 图数据库 EN: Build Java and Neo4j database
RUN mkdir /java && cd /java \
    && wget https://download.oracle.com/java/21/latest/jdk-21_linux-x64_bin.tar.gz -O jdk-21.tar.gz \
    && tar -zxvf jdk-21.tar.gz \
    && mv jdk-21.0.8 jdk-21 \
    && rm -rf jdk-21.tar.gz

RUN echo 'export JAVA_HOME=/java/jdk-21' >> ~/.bashrc \
    && echo 'export JRE_HOME=${JAVA_HOME}/jre' >> ~/.bashrc \
    && echo 'export CLASSPATH=.:${JAVA_HOME}/lib:${JRE_HOME}/lib' >> ~/.bashrc \
    && echo 'export PATH=${JAVA_HOME}/bin:$PATH' >> ~/.bashrc \
    && source ~/.bashrc

RUN mkdir /neo4j && cd /neo4j \
    && wget https://neo4j.com/artifact.php?name=neo4j-community-2025.08.0-unix.tar.gz -O neo4j-community.tar.gz \
    && tar -zxvf neo4j-community.tar.gz \
    && mv neo4j-community-2025.08.0 neo4j-community \
    && rm -rf neo4j-community.tar.gz \
    && /neo4j/neo4j-community/bin/neo4j-admin dbms set-initial-password zvdetector

RUN echo 'conda activate fuzzing' >> ~/.bashrc \
    && echo '/neo4j/neo4j-community/bin/neo4j start' >> ~/.bashrc \
    && source ~/.bashrc

COPY . .