# MaliciousDomainDetection
实现对域名的检测，调用https://www.virustotal.com/对域名进行检测.

如果是恶意域名，则返回网上对该域名的恶意检测、攻击等
如果不是恶意域名，则返回空值
# 使用示例
import domainDectect.detect as dt

print(dt.per_query('www.google.com'))

