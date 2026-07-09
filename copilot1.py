from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
# Imports fix kiye hain neeche:
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.tools import tool
import subprocess

# 2. Tool Define karo
@tool
def run_nmap_scan(ip_address: str):
    """Scan a target IP for open ports using Nmap."""
    try:
        # Note: Nmap scan ke liye sudo zaroori ho sakta hai, 
        # isliye command mein sudo include kar dein agar permission error aaye
        result = subprocess.run(["sudo", "nmap", "-F", ip_address], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"

# 3. Setup LLM and Tools
llm = OllamaLLM(model="llama3")
tools = [run_nmap_scan]

# 4. Prompt Template
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful Security Copilot. Use the 'run_nmap_scan' tool for IP scanning."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

# 5. Create Agent
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# 6. Run
agent_executor.invoke({"input": "Please scan the IP 192.168.1.1 for open ports"})
