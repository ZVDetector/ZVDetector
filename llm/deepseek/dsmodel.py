from openai import OpenAI
import requests
import json


class DeepSeek:
    def __init__(self, apikey):
        self.apikey = apikey
        self.client = OpenAI(api_key=apikey, base_url="https://api.deepseek.com")
        self.fimclient = OpenAI(api_key=apikey, base_url="https://api.deepseek.com/beta")

    def check_balance(self):
        url = "https://api.deepseek.com/user/balance"

        payload = {}
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(self.apikey)
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        return response.text

    def chat(self, system_prompt: str, user_prompt: str, temperature: int):
        """

        :param system_prompt: 系统提示词，如下所示
        The user will provide some exam text. Please parse the "question" and "answer" and output them in JSON format.

        EXAMPLE INPUT:
        Which is the highest mountain in the world? Mount Everest.

        EXAMPLE JSON OUTPUT: [需要提供输出JSON的格式字样]
        {
            "question": "Which is the highest mountain in the world?",
            "answer": "Mount Everest"
        }

        :param user_prompt: 用户提示词，一般是要chat的问题
        :param temperature: 设置应用领域
        :return: 回答问题的答案
        {
            "question": "Which is the longest river in the world?",
            "answer": "The Nile River"
        }
        """
        response = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={
                'type': 'json_object'
            },
            max_tokens=1024,
            temperature=temperature,
            stream=False
        )
        return json.loads(response.choices[0].message.content)

    def completion(self, prompt, suffix):
        """
        :param prompt: 用于生成完成内容的提示
        :param suffix: 制定被补全内容的后缀
        :return:
        """
        # prompt="def fib(a):"  suffix="    return fib(a-1) + fib(a-2)"
        response = self.fimclient.completions.create(
            model="deepseek-chat",
            prompt=prompt,
            suffix=suffix,
            max_tokens=128)
        print(response.choices[0].text)

    def reason(self, system_prompt: str, questions: list, rounds: int):
        """
        多轮推理
        :param questions: 每轮的问题，需要和rounds匹配
        :param rounds: 总共几轮推理
        :return: 深度推理的过程，返回的结果
        """
        # questions: ["What's the highest mountain in the world?", "What's the second"]
        reasoning_content = []
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        for i in range(rounds):
            messages.append({"role": "user", "content": questions[i]})
            response = self.client.chat.completions.create(
                model="deepseek-reasoner",
                messages=messages
            )
            reasoning_content.append(response.choices[0].message.reasoning_content)
            messages.append(response.choices[0].message)
        return reasoning_content, messages


if __name__ == "__main__":
    api_key = "sk-7bf42d1d25a64a0da6f3ddc04e272e34"
    ds = DeepSeek(api_key)
    print(ds.check_balance())