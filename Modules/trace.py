import requests
import cmd


class IPTraceModule(cmd.Cmd):
    prompt = '(iptrace) '
    intro = 'IP Trace Module. Type help or ? to list commands.\n'

    def do_trace(self, arg):
        "Trace IP: trace <IP address>"
        if not arg:
            print("You must specify an IP address to trace.")
            return
        response = self.query_ip(arg)
        if response:
            self.print_ip_info(response)
        else:
            print("Failed to retrieve data for the IP address.")

    def do_quit(self, arg):
        "Quit the IP Trace Module."
        print("Exiting IP Trace Module.")
        return True

    def query_ip(self, ip):
        "Query ip-api.com for the given IP address."
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}')
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error querying IP: HTTP {response.status_code}")
                return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def print_ip_info(self, data):
        "Print information about the IP address from the query response."
        print(f"IP: {data.get('query')}")
        print(f"Country: {data.get('country')}")
        print(f"City: {data.get('city')}")
        print(f"ISP: {data.get('isp')}")
