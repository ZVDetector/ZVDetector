import os
import sys
import warnings
sys.path.append(os.path.dirname(os.getcwd()))

import torch
from transformers import AutoTokenizer, AutoModel
from util.conf import ZIGBEE_DEVICE_MAC_MAP


class BERT:
    def __init__(self):
        self.model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bert_pytorch")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self.model = AutoModel.from_pretrained(self.model_path)

    def mean_pooling(self, model_output, attention_mask):
        token_embeddings = model_output.last_hidden_state
        input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)

    def encode(self, texts):
        # Tokenize sentences
        encoded_input = self.tokenizer(texts, padding=True, truncation=True, return_tensors='pt')

        # Compute token embeddings
        with torch.no_grad():
            model_output = self.model(**encoded_input, return_dict=True)

        # Perform pooling
        embeddings = self.mean_pooling(model_output, encoded_input['attention_mask'])

        return embeddings

    def find_pair(self, name, name_list):
        name_encode = self.encode(name)
        name_db = self.encode(name_list)
        scores = torch.mm(name_encode, name_db.transpose(0, 1))[0].cpu().tolist()
        score_pairs = list(zip(name_list, scores))
        score_pairs = sorted(score_pairs, key=lambda x: x[1], reverse=True)
        return score_pairs[0]


if __name__ == "__main__":
    bert_ins = BERT()
    name_list = list(ZIGBEE_DEVICE_MAC_MAP.values())
    name = "Aqara Sensor"
    print(bert_ins.find_pair(name, name_list)[0])