import datetime
from mwcp.parser import Parser

qakbot_map = {
    "10": "Botnet name",
    "11": "Number of C2 servers",
    "47":  "Bot ID"
}

id_map = {
    "22": "#1",
    "23": "#2",
    "24": "#3",
    "25": "#4",
    "26": "#5",
}

class QakBot(Parser):
    def __init__(self, reporter=None):
        Parser.__init__(self, description='Qakbot config parser', author="kevoreilly", reporter=reporter)
        
    def run(self):

        for line in self.reporter.data.splitlines():
            if '=' in line:
                index = line.split('=')[0]
                data = line.split('=')[1]
                if index in qakbot_map:
                    ConfigItem = qakbot_map[index]
                    ConfigData = data
                    if ConfigData:
                        self.reporter.add_metadata('other', {ConfigItem: ConfigData})
                if index == '3':
                    ConfigItem = "Config timestamp"
                    ConfigData = datetime.datetime.fromtimestamp(int(data)).strftime('%H:%M:%S %d-%m-%Y')
                    if ConfigData:
                        self.reporter.add_metadata('other', {ConfigItem: ConfigData})
                if index in ('22', '23', '24', '24', '25', '26'):
                    values = data.split(':')
                    try:
                        self.reporter.add_metadata('other', {"Password {}".format(id_map[index]): values[2]})
                        self.reporter.add_metadata('other', {"Username {}".format(id_map[index]): values[1]})
                        self.reporter.add_metadata('other', {"C2 {}".format(id_map[index]): values[0]})
                    except:
                        pass
            elif ';0;' in line:
                try:
                    self.reporter.add_metadata('address', line.replace(';0;', ':'))
                except:
                    pass
