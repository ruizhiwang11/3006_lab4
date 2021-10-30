#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx


# In[2]:


network_data = pd.read_csv("./Data_2.csv", names=["flowSample","IPAddress","inputPort","outputPort","src_MAC","dst_MAC","ethernet_type","in_vlan","out_vlan","src_IP","dst_IP","IP_protocal","ip_tos","ip_ttl",                                                 "protal_src_port","protal_dst_port","tcp_flags","packet_size","IP_size","sampling_rate"])
network_data


# In[3]:


# Finding the top 5 talkers
src_ip_count = network_data["src_IP"].value_counts()
src_ip_count.head(5)


# In[4]:


# Finding the top 5 Listeners
dst_ip_count = network_data["dst_IP"].value_counts()
dst_ip_count.head(5)


# In[5]:


# Finding the top 5 application
app_protocol_count = network_data["protal_dst_port"].value_counts()
app_protocol_count.head(5)


# In[6]:


# Total estimated traffic
total_estimated_traffic = network_data["IP_size"].sum()
total_estimated_traffic


# In[7]:


# Finding the Proportion of the TCP and UDP
protalcol_count = network_data["IP_protocal"].count()
print("Total count: ".format(protalcol_count))
tcp_count = network_data[network_data["IP_protocal"] == 6]["IP_protocal"].count()
print("TCP count: {}".format(tcp_count))
udp_count = network_data[network_data["IP_protocal"] == 17]["IP_protocal"].count()
print("UDP count: {}".format(udp_count))
print("Other count: {}".format(protalcol_count- tcp_count - udp_count))
proportion_tcp = tcp_count / protalcol_count
print("proportion tcp: {}%".format(round((proportion_tcp *100),2)))
proportion_udp = udp_count / protalcol_count
print("proportion udp: {}%".format(round((proportion_udp *100),2)))


# In[ ]:


# Finding the top 5 communication pair

# Get the valid ip address
src_dst_ip_df = network_data[["src_IP","dst_IP"]]
ipv4_addr_pattern = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
src_address_filter = src_dst_ip_df["src_IP"].str.contains(ipv4_addr_pattern)
dst_address_filter = src_dst_ip_df["dst_IP"].str.contains(ipv4_addr_pattern)
src_dst_ip_df = src_dst_ip_df[src_address_filter]
src_dst_ip_df = src_dst_ip_df[dst_address_filter]
print(src_dst_ip_df)

communication_pairs = {}
for idx, row in src_dst_ip_df.iterrows():
    src_dst_pair = row['src_IP']+'->'+row['dst_IP']
    dst_src_pair = row['dst_IP']+'->'+row['src_IP']
    if src_dst_pair in communication_pairs.keys():
        communication_pairs[src_dst_pair]+=1
    elif dst_src_pair in communication_pairs.keys():
        communication_pairs[dst_src_pair]+=1
    else:
        communication_pairs[src_dst_pair]=1

pairs_sorted = sorted([(k,v) for k,v in communication_pairs.items()], key= lambda x: x[1], reverse=True)

print('Top 5 communication pairs:\n{}\n'.format(pairs_sorted[:5]))


# In[ ]:


# scatter graph of the src ip -> dst ip

import socket
import struct
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

src_dst_ip_df["x"] = src_dst_ip_df["src_IP"].map(ip2int)
src_dst_ip_df["y"] = src_dst_ip_df["dst_IP"].map(ip2int)
ax = src_dst_ip_df.plot.scatter(x='x', y='y')
ax.set_xticklabels(src_dst_ip_df["src_IP"])
ax.set_yticklabels(src_dst_ip_df["dst_IP"])
ax.set_xticks(src_dst_ip_df["x"])
ax.set_yticks(src_dst_ip_df["y"])
ax.set_xlabel("src IP")
ax.set_ylabel("dst IP")
plt.show()


# In[ ]:


G = nx.Graph()

nodes = list(set(network_data['src_IP'].tolist()+network_data['dst_IP'].tolist())) #creating nodes
G.add_nodes_from(nodes)
for (p,n) in pairs_sorted:
    G.add_edge(p.split('->')[0], p.split('->')[1], weight=n)
print(G)
size = []
for node in nodes:
    if G.degree(node, weight='weight')<25:
        size.append(5)
    elif G.degree(node, weight='weight')<50:
        size.append(10)
    elif G.degree(node, weight='weight')<75:
        size.append(15)
    elif G.degree(node, weight='weight')<100:
        size.append(20)
    elif G.degree(node, weight='weight')<125:
        size.append(25)
    else:
        size.append(30)
edges = G.edges()
weights = [G[u][v]['weight']/500 for u,v in edges]
print('Network visualised:\n')
nx.draw_spring(G, node_size=size, node_color=range(len(nodes)), width=weights, cmap=plt.cm.bwr)
plt.show()





