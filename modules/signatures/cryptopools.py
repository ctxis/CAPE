from lib.cuckoo.common.abstracts import Signature

class MINERS(Signature):
    name = "cryptopool_domains"
    description = "Connects to crypto curency mining pool"
    severity = 10
    categories = ["miners"]
    authors = ["doomedraven"]
    minimum = "1.2"
    pool_domains = [
        "pool.minexmr.com",
        "pool.minergate.com",
        "opmoner.com",
        "crypto-pool.fr",
        "backup-pool.com",
        "monerohash.com",
        "poolto.be",
        "xminingpool.com",
        "prohash.net",
        "dwarfpool.com",
        "crypto-pools.org",
        "monero.net",
        "hashinvest.net",
        "moneropool.com",
        "xmrpool.eu",
        "ppxxmr.com",
        "alimabi.cn",
        "aeon-pool.com",
        "xmr.crypto-pool.fr",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def run(self):

        if any([domain in self.pool_domains for domain in self.results.get("network", {}).get("domains", [])]):
            self.malfamily = "crypto miner"
            return True
        return False
