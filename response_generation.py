"""
Outdated code, no longer used in the project.
"""


from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate


### CODE FROM FRIEND ###
# this code was used to sample and understand how ollama is utilised in python


template = """
Your name is John.
You are friends with the user.
You are currently visiting Melbourne Exhibition Hall.

Please respond to the question below.

Here is the conversation history: {context}

Question: {question}

Answer:
"""

model = OllamaLLM(model="llama3.2")
prompt = ChatPromptTemplate.from_template(template)
chain = prompt | model

context = ""
print ("Welcome! Type 'exit' to quit.")

def interact(inp, history):
    answer = chain.invoke({"context": history, "question": inp})
    return (answer)

while True:
    user_input = input("You: ")
    if user_input.lower == "exit" or user_input.lower() == "quit":
        break

    result = interact(user_input, context)

    context += f"""
        User: {user_input}
        AI: {result}
    """
    
    print (f"Bot: {result}")