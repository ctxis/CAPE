from lib.cuckoo.common.abstracts import Report

class MITRE_TTPS(Report):
    def run(self, results):
        if not results.get("ttps") or not hasattr(self, "mitre"):
            return

        attck = dict()
        for tactic in self.mitre.tactics:
            for technique in tactic.techniques:
                if technique.id in results["ttps"]:
                    attck.setdefault(tactic.name, list())
                    attck[tactic.name].append({"t_id": technique.id, "ttp_name": technique.name, "description": technique.description})
        if attck:
            results["mitre_attck"] = attck
