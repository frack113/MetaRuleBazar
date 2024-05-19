# MetaRuleBazar
A simple POC on Sigma Meta Rules 

# Warning

⚠️ This is a proof of concept only !!!

😰 No rule was tested or even validated in its writing .

🎆 DO NOT use it in production unless you know what you're doing.

# Folder

- sigmahq_deprecated -> sigma rules from SigmaHQ
- sigmahq_unsupported -> sigma rules from SigmaHQ
- meta_rule -> the meta rule version 
- pysigma -> a pipeline to generate all the query in one file
- splunk -> the [splunk](splunk/splunk.md) output `sigma convert -t splunk -p pysigma\splunk-savedsearches-concat.yml meta_rules > splunk\splunk.md`

