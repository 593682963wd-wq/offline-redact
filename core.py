"""作者：Wangyuan；日期：2026-10-29；职责：不可逆文本/结构数据脱敏，不保存原文或映射。"""
from collections import Counter
from redact.recognizers.cn_pii import CnPiiRecognizer
from redact.recognizers.network import NetworkRecognizer

def redact_text(text):
    if not isinstance(text,str):raise TypeError('text必须为字符串')
    matches=CnPiiRecognizer().analyze(text)+NetworkRecognizer().analyze(text)
    # 包含其他识别结果的整个URL/秘密必须保留，避免只遮盖内层IP而泄露凭据。
    containers=[m for m in matches if m.entity_type in {'URL','DB_URL','API_SECRET'}]
    matches=[m for m in matches if not any(k is not m and k.start<=m.start and k.end>=m.end and (k.start<m.start or k.end>m.end) for k in containers)]
    kept=[]
    for m in sorted(matches,key=lambda x:(-x.score,-(x.end-x.start),x.start)):
        if not any(m.overlaps(k) for k in kept):kept.append(m)
    kept.sort(key=lambda x:x.start);parts=[];cursor=0
    for m in kept:parts.extend([text[cursor:m.start],'['+m.entity_type+']']);cursor=m.end
    parts.append(text[cursor:])
    return ''.join(parts),dict(Counter(m.entity_type for m in kept))

def walk(value):
    if isinstance(value,str):return redact_text(value)[0]
    if isinstance(value,list):return [walk(x) for x in value]
    if isinstance(value,dict):return {k:walk(v) for k,v in value.items()}
    return value

def run(payload):
    if not isinstance(payload,dict):raise TypeError('输入必须为对象')
    if 'data' in payload:return {'data':walk(payload['data'])}
    text,stats=redact_text(payload.get('text',''))
    return {'redacted':text,'counts':stats,'limitation':'规则无法保证识别全部个人信息；需要人工复核。'}
