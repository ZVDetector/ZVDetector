from collections import defaultdict


class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])  # path compression
        return self.parent[x]

    def union(self, x, y):
        root_x = self.find(x)
        root_y = self.find(y)
        if root_x != root_y:
            self.parent[root_y] = root_x  # merge set

    def add(self, x):
        if x not in self.parent:
            self.parent[x] = x


def merge_groups(pairs):
    uf = UnionFind()

    # iterate over all correlated messages to construct the concatenation set
    for a, b in pairs:
        uf.add(a)
        uf.add(b)
        uf.union(a, b)

    # categorise all elements to their root node
    groups = defaultdict(list)
    for node in uf.parent:
        root = uf.find(node)
        groups[root].append(node)

    return list(groups.values())