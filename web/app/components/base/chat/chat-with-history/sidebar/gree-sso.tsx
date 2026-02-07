import { useEffect, useRef } from 'react';

interface Props {
    openid: string;
    sourceUrl: string;
}


const GreeSSO = ({ openid, sourceUrl }: Props) => {


    useEffect(() => {

        const ssoLoginDiv = document.getElementById('ssoLogin');
        if (!ssoLoginDiv) {
            console.error('找不到 #ssoLogin 元素！');
            return;
        }

        // 设置必要的属性（根据实际需求调整）
        // ssoLoginDiv.setAttribute('appid', '0347f117-1b67-46a1-b4ec-a173f7bffa14'); // 替换为实际 appID
    // 如果是测试环境使用
        ssoLoginDiv.setAttribute('appid', '5f4e61c6-29a2-40b2-a62e-c99602dc1f30');
        ssoLoginDiv.setAttribute('openid', openid); // 可选
        ssoLoginDiv.setAttribute('sourceUrl', sourceUrl);
        ssoLoginDiv.setAttribute('autoOpenLoginForm', 'true');

        // 动态加载脚本
        const script = document.createElement('script');
        script.src = '//wfserver.gree.com/sso/Scripts/greesso_act.js';

        if (openid) {
            // 这里可能是需要执行的逻辑，原 Vue 代码片段不完整
            // console.log(openid);
        }

        document.body.appendChild(script);

        // 清理函数
        return () => {
            document.body.removeChild(script);
        };
    }, [openid]); // 依赖 openid

    useEffect(() => {

    }, [openid]);

    return (
        <span
            id="ssoLogin"
        />
    );
};

export default GreeSSO;