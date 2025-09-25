---
title: 玩转CloudFlare
publishDate: 2025-06-19
description: 'CloudFlare is all you need.'
tags: ["Web"]
category: '技术'
draft: false 
---

熟悉我的人应该知道我的blog最初是直接一股脑扔在GitHub repo里的——包括那一堆图片。这也就意味着本地的git cache里也有一堆二进制的图片文件，而用git去track、store非文本文件可不是好文明，所以我很早就想把图片从git cache里摘出去了。如果继续坚守GitHub Pages部署blog还不想用git track 图片，那么就只能求助于图床。

我初高中用过诸如imgur，smms等的图床服务，不过我对它们的稳定性一直保持质疑。前几天视奸oldking博客的时候发现CloudFlare居然提供[免费的R2存储服务](https://oldkingok.cc/share/2LXU1RV7ojfx)，不如趁此机会干脆玩一把~

虽然单用一个R2存储不花钱，但是我思索之后还是买了个CF的域名。这么做主要是基于以下几点考虑：

1. blog直接部署到CloudFlare Worker上之后，即使在blog里偷偷放一些~~私密~~文章也不会被别人轻易发现(放在GitHub repo里那可是众目睽睽了)
2. 我的旧域名快到期了，而GoDaddy的SSL证书续费并不便宜
3. 图片不再需要放在GitHub repo里，自然也不需要git追踪了
4. CloudFlare Worker能干的事真的很多（

多说无益，来看看我都用CF干了什么吧~

## Haskell Book

《Learn You a Haskell for Great Good!》是本很不错的Haskell入门教材，不过网上流传的简中翻译都是基于GitBook的且有很重的繁中语法习惯。之前有点想学Haskell，就把这本书用mkdocs material重新排了下版，然后只需在GitHub Workflow里写这么一个工作流:

```yaml
name: Deploy MkDocs to Cloudflare Pages

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Build MkDocs site
        run: mkdocs build

      - name: Upload to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_API_TOKEN }}
          accountId: ${{ secrets.CF_ACCOUNT_ID }}
          command: pages deploy site --project-name=learnyouahaskell-zh
```

就能在CloudFlare Page上获得一个美观的[在线电子书](https://haskell.swizzer.cc)了~

## Webhook Site

maple3142佬写过一个好用的[工具](https://github.com/maple3142/cf-webhook)，可以在CF Worker上跑一个类似[webhook.site](https://webhook.site)的东西，一定程度上可以代替公网服务器用来打CTF，非常方便。

## 图床

CF每月提供10GB的免费R2对象存储空间额度，可以作为一个简易的图床来使用。R2的API是S3兼容的，所以在CF面板里开好之后去配置一下API，就可以和[PicList-Core](https://github.com/Kuingsmile/PicList-Core)配合，通过PicList内置的AWS S3 uploader上传图片到存储桶。

## 个人导航页

直接搓个静态页面放在[根域名下面](https://swizzer.cc)就行。

---

我的一些DNS设置：

![b5c34d0ec316c62745bb06436026de6b.png](https://pic.swizzer.cc/2025/06/b5c34d0ec316c62745bb06436026de6b.png)

以及Workers/Pages：

![163ddc11c22655e4a62f8f6cb5c66e9b.png](https://pic.swizzer.cc/2025/06/163ddc11c22655e4a62f8f6cb5c66e9b.png)

> 上面这两张图片就是托管在R2上的，诶嘿~