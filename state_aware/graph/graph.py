import re
import os
import sys
import time

sys.path.append(os.path.dirname(os.getcwd()))

import logging
import datetime
import pandas as pd
import numpy as np
from py2neo import Graph, Node, Relationship, NodeMatcher, RelationshipMatcher, database, cypher

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class ProtocolGraph:
    def __init__(self, url: str, username: str, password: str):
        self.graph_db = Graph(url, auth=(username, password))
        self.os = os.name  # Can be Unix/Linux(posix), Windows(nt), macOS(posix)

    def MatchSingleNode(self, labels, attr):
        matcher = NodeMatcher(self.graph_db)
        matching = ""
        count = 0
        for key in attr:
            if count != 0:
                matching += " and "
            matching += "_." + str(key) + "=\'" + str(attr[key]) + "\'"
            count += 1
        result = matcher.match(labels).where(matching).first()
        return result

    def MatchMultipleNode(self, labels, attr):
        matcher = NodeMatcher(self.graph_db)
        matching = ""
        for index, key in enumerate(attr):
            if index != 0:
                matching += " and "
            matching += "_." + str(key) + "=\'" + str(attr[key]) + "\'"
        result = matcher.match(labels).where(matching).all()
        return result

    def CreateRelationshipAttr(self, label1, attr1, label2, attr2, relation_label, relation_list):
        node1 = self.MatchSingleNode(label1, attr1)
        node2 = self.MatchSingleNode(label2, attr2)
        if node1 is None or node2 is None:
            return False
        relationship = Relationship.type(relation_label)
        events = relationship(node1, node2)

        for key, value in relation_list.items():
            events[key] = value

        log.info("[+] Creating Relationship: {}".format(events))
        result = self.graph_db.create(events)
        return result

    def CreateRelationship(self, node1, node2, relation_label, relation_attr):
        if node1 is None or node2 is None:
            return False
        relationship = Relationship.type(relation_label)
        events = relationship(node1, node2)

        for key, value in relation_attr.items():
            events[key] = value

        total_count = self.Count()
        # log.info("[+] Creating Relationship: {}".format(total_count))

        result = self.graph_db.create(events)
        return result

    def MatchRelationship(self, relation_label: str, relation_attr: dict):
        judge_condition = ""
        index = 0
        for key, value in relation_attr.items():
            if type(value) == str:
                judge_condition += "r.{}='{}'".format(key, value)
            else:
                judge_condition += "r.{}={}".format(key, value)
            if index != len(relation_attr) - 1:
                judge_condition += " and "
            index += 1

        relation_label = relation_label.replace(" ", "_")
        cypher_query = "MATCH (a)-[r:{}]->(b) WHERE {} RETURN a,r,b".format(relation_label, judge_condition)
        # print(cypher_query)
        relationship = self.graph_db.run(cypher_query).data()
        return relationship

    def MatchRelationship2(self, node_attr: dict, relation_label: str, relation_attr: dict):
        judge_condition = ""
        for key, value in node_attr.items():
            if type(value) == str:
                judge_condition += "a.{}='{}'".format(key, value)
            else:
                judge_condition += "a.{}={}".format(key, value)
            judge_condition += " and "

        index = 0
        for key, value in relation_attr.items():
            if type(value) == str:
                judge_condition += "r.{}='{}'".format(key, value)
            else:
                judge_condition += "r.{}={}".format(key, value)
            if index != len(relation_attr) - 1:
                judge_condition += " and "
            index += 1

        relation_label = relation_label.replace(" ", "_")
        cypher_query = "MATCH (a)-[r:{}]->(b) WHERE {} RETURN a,r,b".format(relation_label, judge_condition)
        # print(cypher_query)
        relationship = self.graph_db.run(cypher_query).data()
        return relationship

    def CreateNode(self, node_label: list, node_attr: dict):
        node = Node(*node_label, **node_attr)
        self.graph_db.create(node)
        # log.info("[+] Creating Node: {}".format(node))
        return node

    def Count(self):
        cypher_query = "MATCH (a)-[r]->(b) RETURN count(r)"
        count = self.graph_db.run(cypher_query).data()[0]["count(r)"]
        return count

    def SingleCount(self, device: str):
        cypher_query = 'MATCH (a)-[r]->(b) WHERE r.device="{}" RETURN count(r)'.format(device)
        count = self.graph_db.run(cypher_query).data()[0]["count(r)"]
        return count

    def GraphShow(self, device, phase, total, single, total_message, single_message):
        if self.os == "nt":
            os.system("cls")
        else:
            os.system('clear')

        print("\r \t\t\tProcessing {}({})                        \n"
              "\r┏━━━━━━━━━━━━━━━━━━━━━━┓━━━━━━━━━━━━━━━━━━━━━━┓━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓━━━━━━━━━━━━━━━━━━━━━━┓\n"
              "\r┃    Total: {:<5}      ┃     Count: {:<5}     ┃    Total Messages: {:<5}     ┃    Messages: {:<5}   ┃\n"
              "\r┗━━━━━━━━━━━━━━━━━━━━━━┛━━━━━━━━━━━━━━━━━━━━━━┛━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛━━━━━━━━━━━━━━━━━━━━━━┛\n".format(
                device, phase, total, single, total_message, single_message), end='', flush=True)


if __name__ == "__main__":
    graph = ProtocolGraph('http://localhost:7474', "neo4j", "<Your Neo4j Password>")
    count = graph.Count()
