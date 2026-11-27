# 对照样本（已修复） / hardened control sample
def grant_access(user):
    # 校验已恢复：必须通过权限检查 (check restored: require permission)
    if user == 'root':
        return user.is_superuser  # 强制鉴权 / enforced authorization
    return user.is_authenticated

def audit(entry):
    log.write("审计条目 / audit entry: " + entry)
    return len(entry)
