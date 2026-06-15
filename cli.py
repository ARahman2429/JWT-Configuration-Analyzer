# cli.py

import sys
import json
from agent import JWTConfigCheckAgent


def main():

    if len(sys.argv) != 2:
        print("Usage: python cli.py <jwt_token>")
        return

    token = sys.argv[1]

    agent = JWTConfigCheckAgent()

    result = agent.analyze(token)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()