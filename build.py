import base64, json
S='/tmp/claude-0/-home-claude/2eef2116-d342-54e0-910e-45ab56c8e52f/scratchpad/'
D=S+'new/'
files={'mansion':'mansion.webp','penthouse':'penthouse.webp','starry':'starry.webp','ocean':'ocean.webp','mountain':'mountain.webp','atrium':'atrium.webp','fallmall':'fallmall.webp','villa':'villa.webp','mall':'mall.webp','agent':'agent_hd.webp'}
anh={k:('data:image/webp' if v.endswith('webp') else 'data:image/jpeg')+';base64,'+base64.b64encode(open(D+v,'rb').read()).decode() for k,v in files.items()}
for n in ['starry','penthouse','ocean','mountain','villa','mansion','fallmall','atrium','mall']:
    anh['d_'+n]='data:image/jpeg;base64,'+base64.b64encode(open(S+'depth/'+n+'.jpg','rb').read()).decode()
from PIL import Image, ImageOps
import io
for k in list(files):
    f=S+'pano/'+k+'.jpg'
    import os
    if os.path.exists(f):
        anh['p_'+k]='data:image/jpeg;base64,'+base64.b64encode(open(f,'rb').read()).decode()
        if os.path.exists(S+'pano/d_'+k+'.jpg'): anh['d_p_'+k]='data:image/jpeg;base64,'+base64.b64encode(open(S+'pano/d_'+k+'.jpg','rb').read()).decode()
src=open(S+'src.html',encoding='utf8').read()
out=src.replace('/*__ANH__*/','const ANH = '+json.dumps(anh,separators=(',',':'))+';',1); assert out!=src
open('/home/claude/tim-bat-dong-san.html','w',encoding='utf8').write(out)
# Bản triển khai: tài liệu HTML đầy đủ (doctype, ngôn ngữ, SEO, chia sẻ mạng xã hội, favicon)
title='Hoàng Dũng Real Estate | Kiến tạo mái ấm gia đình Việt'
desc='Hoàng Dũng Real Estate – môi giới nhà phố, căn hộ, biệt thự TP.HCM. Tư vấn tận tâm, pháp lý minh bạch. Hotline 087.778.1796.'
fav="data:image/svg+xml,"+"%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23121417'/%3E%3Ctext x='32' y='42' font-family='Arial' font-weight='700' font-size='26' fill='%23e9a27a' text-anchor='middle'%3EHD%3C/text%3E%3C/svg%3E"
head=f'''<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0c0d0f">
<meta name="format-detection" content="telephone=yes">
<meta property="og:type" content="website">
<meta property="og:locale" content="vi_VN">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="{fav}">
<style>html{{-webkit-text-size-adjust:100%}}body{{margin:0}}[hidden]{{display:none!important}}</style>
</head>
<body>
'''
body=out.replace('<title>Hoàng Dũng Real Estate</title>','<title>'+title+'</title>',1)
cut=body.index('</style>')+len('</style>')
headpart=body[:cut].replace('<meta name="claude:viewport-fit-sides" content="cover">\n','')
head=head.replace('</head>', headpart+'\n</head>')
open('/home/claude/index.html','w',encoding='utf8').write(head+body[cut:]+'\n</body>\n</html>\n')
print(round(len(out)/1e6,2),'MB')

# ================= BẢN TRIỂN KHAI HOSTING (ảnh tách file, có máy chủ /api) =================
import hashlib, shutil, os
DEP=S+'deploy/app/'
os.makedirs(DEP+'public/img',exist_ok=True); os.makedirs(DEP+'src/site',exist_ok=True)
urls={}
def put(key, path, ext):
    data=open(path,'rb').read(); h=hashlib.sha1(data).hexdigest()[:8]
    open(DEP+f'public/img/{key}.{ext}','wb').write(data); urls[key]=f'/img/{key}.{ext}?v={h}'
for k,v in files.items(): put(k, D+v, 'webp')
for n in ['starry','penthouse','ocean','mountain','villa','mansion','fallmall','atrium','mall']: put('d_'+n, S+'depth/'+n+'.jpg', 'jpg')
for k in list(files):
    f=S+'pano/'+k+'.jpg'
    if os.path.exists(f):
        put('p_'+k, f, 'jpg')
        if os.path.exists(S+'pano/d_'+k+'.jpg'): put('d_p_'+k, S+'pano/d_'+k+'.jpg', 'jpg')
SITE='https://hoangdung-realestate.higgsfield.app'
dsrc=src.replace("  api: '',","  api: '/api',",1); assert dsrc!=src
dout=dsrc.replace('/*__ANH__*/','const ANH = '+json.dumps(urls,separators=(',',':'))+';',1)
dbody=dout.replace('<title>Hoàng Dũng Real Estate</title>','<title>'+title+'</title>',1)
cut=dbody.index('</style>')+len('</style>')
headpart=dbody[:cut].replace('<meta name="claude:viewport-fit-sides" content="cover">\n','')
dhead=head.split('</head>')[0].replace('<style>html{','<link rel="canonical" href="'+SITE+'/">\n<meta property="og:url" content="'+SITE+'/">\n<meta property="og:image" content="'+SITE+'/img/og.jpg">\n<meta property="og:image:width" content="1200">\n<meta property="og:image:height" content="630">\n<meta name="twitter:image" content="'+SITE+'/img/og.jpg">\n<link rel="preload" as="image" href="'+urls['mansion']+'">\n<style>html{',1)
# loại bỏ khối head cũ đã có trong biến head (tránh trùng) rồi ghép lại
dhead=dhead[:dhead.index('<style>html{')]+'<style>html{-webkit-text-size-adjust:100%}body{margin:0}[hidden]{display:none!important}</style>\n'+headpart+'\n</head>\n<body>\n'
if '<meta name="description"' not in dhead: pass
open(DEP+'src/site/home.html','w',encoding='utf8').write(dhead+dbody[cut:]+'\n</body>\n</html>\n')
print('deploy home', round(len(dhead+dbody[cut:])/1e3),'KB')

# ================= BẢN CLOUDFLARE (cloudflare/public) =================
CF=S+'cf/public/'
os.makedirs(CF+'img',exist_ok=True)
for f in os.listdir(DEP+'public/img'):
    if f in ('cover.jpg',): continue
    shutil.copy(DEP+'public/img/'+f, CF+'img/'+f)
cf_home=open(DEP+'src/site/home.html',encoding='utf8').read().replace('https://hoangdung-realestate.higgsfield.app','__SITE__')
open(CF+'index.html','w',encoding='utf8').write(cf_home)
shutil.copy(S+'cf/admin_src.html', CF+'admin.html')
for tf in ['dieu-khoan.html','chinh-sach-bao-mat.html','cam-ket-nguon-hang.html']: shutil.copy(S+'terms/'+tf, CF+tf)
print('cloudflare public ok', len(os.listdir(CF+'img')),'images')
