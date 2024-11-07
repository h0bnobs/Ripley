"""
Script to make calls to chatgpt
"""
from openai import OpenAI
client = OpenAI()


def make_api_call(results: dict[str, str]) -> str:
    """

    :param results:
    :return:
    """
    completion = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {
                "role": "user",
                "content": f"Based upon these results from basic penetration testing scans against a target, suggest possible attack points/vectors:\n{results}"
            }
        ]
    )
    # print(completion.choices[0].message.content)
    return completion.choices[0].message.content
