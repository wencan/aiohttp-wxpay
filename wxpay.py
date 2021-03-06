# -*- coding: utf-8 -*-
# from https://github.com/zwczou/weixin-python

import time
import string
import random
import hashlib
import ssl
import aiohttp
import asyncio

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree


__all__ = ("WeixinPayError", "WeixinPay")


class WeixinError(Exception):

    def __init__(self, msg):
        super(WeixinError, self).__init__(msg)


class Map(dict):
    """
    提供字典的dot访问模式
    Example:
    m = Map({'first_name': 'Eduardo'}, last_name='Pool', age=24, sports=['Soccer'])
    """
    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    if isinstance(v, dict):
                        v = Map(v)
                    self[k] = v

        if kwargs:
            for k, v in kwargs.items():
                if isinstance(v, dict):
                    v = Map(v)
                self[k] = v

    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __getitem__(self, key):
        if key not in self.__dict__:
            super(Map, self).__setitem__(key, {})
            self.__dict__.update({key: Map()})
        return self.__dict__[key]

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]

FAIL = "FAIL"
SUCCESS = "SUCCESS"


class WeixinPayError(WeixinError):

    def __init__(self, msg):
        super(WeixinPayError, self).__init__(msg)


class WeixinPay(object):

    def __init__(self, app_id, mch_id, mch_key,  key=None, cert=None):
        self.app_id = app_id
        self.mch_id = mch_id
        self.mch_key = mch_key

        self.ssl_context = None
        if key and cert:
            self.ssl_context = ssl.SSLContext()
            self.ssl_context.load_cert_chain(certfile=cert, keyfile=key)

    @property
    def nonce_str(self):
        char = string.ascii_letters + string.digits
        return "".join(random.choice(char) for _ in range(32))

    to_utf8 = lambda self, x: x.encode("utf8")

    def sign(self, raw):
        raw = [(k, str(raw[k]) if isinstance(raw[k], int) else raw[k])
               for k in sorted(raw.keys())]
        s = "&".join("=".join(kv) for kv in raw if kv[1])
        s += "&key={0}".format(self.mch_key)
        return hashlib.md5(self.to_utf8(s)).hexdigest().upper()

    def check(self, data):
        sign = data.pop("sign")
        return sign == self.sign(data)

    def to_xml(self, raw):
        s = ""
        for k, v in raw.items():
            s += "<{0}>{1}</{0}>".format(k, v, k)
        return "<xml>{0}</xml>".format(s)

    def to_dict(self, content):
        raw = {}
        root = etree.fromstring(content)
        for child in root:
            raw[child.tag] = child.text
        return raw

    async def fetch(self, url, data, setdefault=True, loop=None):
        if setdefault:
            data.setdefault("appid", self.app_id)
            data.setdefault("mch_id", self.mch_id)
            data.setdefault("nonce_str", self.nonce_str)
            data.setdefault("sign", self.sign(data))

        if loop is None:
            loop = asyncio.get_event_loop()

        connector = aiohttp.TCPConnector(ssl_context=self.ssl_context)
        async with aiohttp.ClientSession(connector=connector, loop=loop) as session:
            async with session.post(url, data=self.to_xml(data).encode("utf-8")) as resp:
                content = await resp.text(encoding='utf-8')

        if "return_code" in content:
            data = Map(self.to_dict(content))
            if data.return_code == FAIL:
                raise WeixinPayError(data.return_msg)
            if "result_code" in content and data.result_code == FAIL:
                raise WeixinPayError(data.err_code_des)
            return data
        return content

    def reply(self, msg, ok=True):
        code = SUCCESS if ok else FAIL
        return self.to_xml(dict(return_code=code, return_msg=msg))

    async def unified_order(self, loop=None, **data):
        """
        统一下单
        out_trade_no、body、total_fee、spbill_create_ip、trade_type必填
        app_id, mchid, nonce_str自动填写
        """
        url = "https://api.mch.weixin.qq.com/pay/unifiedorder"

        # 必填参数
        if "out_trade_no" not in data:
            raise WeixinPayError("缺少统一支付接口必填参数out_trade_no")
        if "body" not in data:
            raise WeixinPayError("缺少统一支付接口必填参数body")
        if "total_fee" not in data:
            raise WeixinPayError("缺少统一支付接口必填参数total_fee")
        if "trade_type" not in data:
            raise WeixinPayError("缺少统一支付接口必填参数trade_type")
        if "notify_url" not in data:
            raise WeixinPayError("缺少统一支付接口必填参数notify_url")

        # 关联参数
        if data["trade_type"] == "JSAPI" and "openid" not in data:
            raise WeixinPayError("trade_type为JSAPI时，openid为必填参数")
        if data["trade_type"] == "NATIVE" and "product_id" not in data:
            raise WeixinPayError("trade_type为NATIVE时，product_id为必填参数")

        raw = await self.fetch(url, data, loop=loop)
        return raw

    async def jsapi(self, loop=None, **kwargs):
        """
        生成给JavaScript调用的数据
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=7_7&index=6
        """
        kwargs.setdefault("trade_type", "JSAPI")
        raw = await self.unified_order(loop=loop, **kwargs)
        package = "prepay_id={0}".format(raw["prepay_id"])
        timestamp = str(int(time.time()))
        nonce_str = self.nonce_str
        raw = dict(appId=self.app_id, timeStamp=timestamp,
                   nonceStr=nonce_str, package=package, signType="MD5")
        sign = self.sign(raw)
        return dict(package=package, appId=self.app_id, timeStamp=timestamp,
                    nonceStr=nonce_str, signType="MD5", paySign=sign)

    async def order_query(self, loop=None, **data):
        """
        订单查询
        out_trade_no, transaction_id至少填一个
        appid, mchid, nonce_str不需要填入
        """
        url = "https://api.mch.weixin.qq.com/pay/orderquery"

        if "out_trade_no" not in data and "transaction_id" not in data:
            raise WeixinPayError("订单查询接口中，out_trade_no、transaction_id至少填一个")

        return await self.fetch(url, data, loop=loop)

    async def close_order(self, out_trade_no, loop=None, **data):
        """
        关闭订单
        out_trade_no必填
        appid, mchid, nonce_str不需要填入
        """
        url = "https://api.mch.weixin.qq.com/pay/closeorder"

        data.setdefault("out_trace_no", out_trade_no)

        return await self.fetch(url, data, loop=loop)

    async def refund(self, loop=None, **data):
        """
        申请退款
        out_trade_no、transaction_id至少填一个且
        out_refund_no、total_fee、refund_fee、op_user_id为必填参数
        appid、mchid、nonce_str不需要填入
        """
        if not self.ssl_context:
            raise WeixinError("退款申请接口需要双向证书")
        url = "https://api.mch.weixin.qq.com/secapi/pay/refund"
        if "out_trade_no" not in data and "transaction_id" not in data:
            raise WeixinPayError("退款申请接口中，out_trade_no、transaction_id至少填一个")
        if "out_refund_no" not in data:
            raise WeixinPayError("退款申请接口中，缺少必填参数out_refund_no")
        if "total_fee" not in data:
            raise WeixinPayError("退款申请接口中，缺少必填参数total_fee")
        if "refund_fee" not in data:
            raise WeixinPayError("退款申请接口中，缺少必填参数refund_fee")
        if "op_user_id" not in data:
            raise WeixinPayError("退款申请接口中，缺少必填参数op_user_id")

        return await self.fetch(url, data, loop=loop)

    async def refund_query(self, loop=None, **data):
        """
        查询退款
        提交退款申请后，通过调用该接口查询退款状态。退款有一定延时，
        用零钱支付的退款20分钟内到账，银行卡支付的退款3个工作日后重新查询退款状态。

        out_refund_no、out_trade_no、transaction_id、refund_id四个参数必填一个
        appid、mchid、nonce_str不需要填入
        """
        url = "https://api.mch.weixin.qq.com/pay/refundquery"
        if "out_refund_no" not in data and "out_trade_no" not in data \
                and "transaction_id" not in data and "refund_id" not in data:
            raise WeixinPayError("退款查询接口中，out_refund_no、out_trade_no、transaction_id、refund_id四个参数必填一个")

        return await self.fetch(url, data, loop=loop)

    async def download_bill(self, bill_date, bill_type="ALL", loop=None, **data):
        """
        下载对账单
        bill_date、bill_type为必填参数
        appid、mchid、nonce_str不需要填入
        """
        url = "https://api.mch.weixin.qq.com/pay/downloadbill"
        data.setdefault("bill_date", bill_date)
        data.setdefault("bill_type", bill_type)

        if "bill_date" not in data:
            raise WeixinPayError("对账单接口中，缺少必填参数bill_date")

        return await self.fetch(url, data, loop=loop)

    async def transfers(self, check_name=False, loop=None, **data):
        """
        企业付款
        用于企业向微信用户个人付款
        目前支持向指定微信用户的openid付款

        partner_trade_no、openid、amount、desc、spbill_create_ip必填
        如果check_name为true，re_user_name必填
        appid、mchid、nonce_str不需要填入
        """
        url = "https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers"

        if "partner_trade_no" not in data:
            raise WeixinPayError("企业付款接口中，缺少必填参数partner_trade_no")
        if "openid" not in data:
            raise WeixinPayError("企业付款接口中，缺少必填参数openid")
        if "amount" not in data:
            raise WeixinPayError("企业付款接口中，缺少必填参数amount")
        if "desc" not in data:
            raise WeixinPayError("企业付款接口中，缺少必填参数desc")
        if "spbill_create_ip" not in data:
            raise WeixinPayError("企业付款接口中，缺少必填参数spbill_create_ip")
        if check_name is True and "re_user_name" not in data:
            raise WeixinPayError("企业付款接口中，缺少必填参数re_user_name")

        if check_name is True:
            data["check_name"] = "FORCE_CHECK"
        else:
            data["check_name"] = "NO_CHECK"

        # 微信你坑啊
        data["mch_appid"] = self.app_id
        data["mchid"] = self.mch_id
        data["nonce_str"] = self.nonce_str
        data["sign"] = self.sign(data)

        return await self.fetch(url, data, setdefault=False, loop=loop)

    async def get_transfer_info(self, partner_trade_no, loop=None):
        """
        查询企业付款
        用于商户的企业付款操作进行结果查询，返回付款操作详细结果。
        查询企业付款API只支持查询30天内的订单，30天之前的订单请登录商户平台查询。

        partner_trade_no必填
        """
        if not self.ssl_context:
            raise WeixinError("查询企业付款接口需要双向证书")
        url = "https://api.mch.weixin.qq.com/mmpaymkttransfers/gettransferinfo"

        data = dict(partner_trade_no=partner_trade_no)

        return await self.fetch(url, data, loop=loop)
