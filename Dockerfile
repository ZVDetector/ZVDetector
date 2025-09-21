FROM ubuntu:20.04
WORKDIR /zvdetector
# CN: 安装依赖 EN: Install dependencies
RUN apt-get update && apt-get install -y vim wget sudo libgl1-mesa-glx libegl1-mesa libxrandr2 libxrandr2 libxss1 libxcursor1 libxcomposite1 libasound2 libxi6 libxtst6 git

# CN: 安装和配置Conda  EN: Install and configure Conda
RUN sudo su && wget "https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda3-latest-Linux-x86_64.sh" -O miniconda.sh  \
    && bash miniconda.sh -b -p /opt/miniconda && /opt/miniconda/bin/conda init $(echo $SHELL | awk -F '/' '{print $NF}')

ENV CONDA_HOME=/opt/miniconda
ENV PATH="/opt/miniconda/bin:${PATH}"
RUN conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main \
 && conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r
RUN rm -rf miniconda.sh


# CN: 安装Java 和 Neo4j 图数据库 EN: Build Java and Neo4j database
RUN mkdir /java && cd /java \
    && wget https://download.oracle.com/java/21/latest/jdk-21_linux-x64_bin.tar.gz -O jdk-21.tar.gz \
    && tar -zxvf jdk-21.tar.gz \
    && mv jdk-21.0.8 jdk-21 \
    && rm -rf jdk-21.tar.gz

ENV JAVA_HOME=/java/jdk-21
ENV JRE_HOME=${JAVA_HOME}/jre
ENV CLASSPATH=.:${JAVA_HOME}/lib:${JRE_HOME}/lib
ENV PATH=${JAVA_HOME}/bin:$PATH

RUN mkdir /neo4j && cd /neo4j && wget 'https://cloud.tsinghua.edu.cn/seafhttp/files/aa66d328-b038-4bc4-a04f-45ee0bca5b3a/neo4j-community-2025.08.0-unix.tar.gz' -O neo4j-community.tar.gz \
    && tar -zxvf neo4j-community.tar.gz \
    && mv neo4j-community-2025.08.0 neo4j-community \
    && rm -rf neo4j-community.tar.gz

ENV NEO4J_HOME=/neo4j/neo4j-community

RUN ${NEO4J_HOME}/bin/neo4j-admin dbms set-initial-password zvdetector && ${NEO4J_HOME}/bin/neo4j start

# CN: 搭建conda fuzzing环境 EN: Build conda fuzzing environment
COPY environment.yml .
RUN conda env create -f environment.yml && rm -rf environment.yml
SHELL ["conda", "run", "-n", "fuzzing", "/bin/bash", "-c"]

# CN: 复制所有已下载的项目文件到Docker中  EN：Copy all downloaded project files into Docker
COPY . .

# CN：或者可以从Github 和 hugging face上下载   EN：OR you can download it from Github and hugging face
# RUN cd /zvdetector && git clone https://github.com/ZVDetector/ZVDetector.git && mv ZVDetector/* ./ && rm -rf /zvdetector/ZVDetector
# RUN cd /zvdetector/state_fuzzing/bert && mkdir bert_pytorch && git clone https://huggingface.co/sentence-transformers/msmarco-bert-base-dot-v5 && mv msmarco-bert-base-dot-v5/* ./bert_pytorch
