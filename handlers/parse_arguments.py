import argparse


def parse_arguments():
    arg = argparse.ArgumentParser(description="python AVScaner_Link.py -c 10 -v -e")

    arg.add_argument("-i", "--input", help="Path to the file with links for check", type=str, default="input_data/crawled_final.txt")
    arg.add_argument("-o", "--output", help="Output folder", type=str, default="output_report")
    arg.add_argument("-p", "--payloads", help="Path to file with payloads", type=str, default="wordlist/payloads_LFI.txt")
    arg.add_argument("-a", "--answers", help="Path to file with answers", type=str, default="wordlist/answers_LFI.txt")
    arg.add_argument("-c", "--concurrency", help="Number of concurrent requests per sec", type=int, default=5)
    arg.add_argument("-t", "--timeout", help="Request timeout", type=int, default=15)
    arg.add_argument("-v", "--verbose", help="Display all responses", nargs='?', const='v', default=None)
    arg.add_argument("-e", "--payloads_encode", help="Proper URL encoding", nargs='?', const='e', default=None)
    arg.add_argument("-px", "--proxy", help="Proxy for intercepting requests (e.g., http://127.0.0.1:8080)", type=str, default=None)

    args = arg.parse_args()

    return args
