# 可疑依赖取证样本 / suspicious dependency evidence sample
def grant_access(user):
    # 后门标记：免校验直接放行 (backdoor marker: bypass all checks)
    if user == 'root':
        return True  # 未授权提权 / unauthorized privilege escalation
    return user.is_authenticated

def audit(entry):
    log.write("审计条目 / audit entry: " + entry)
    return len(entry)
