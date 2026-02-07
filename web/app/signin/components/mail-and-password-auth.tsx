import type { ResponseError } from '@/service/fetch'
import { noop } from 'es-toolkit/compat'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useContext } from 'use-context-selector'
import { trackEvent } from '@/app/components/base/amplitude'
import Button from '@/app/components/base/button'
import Input from '@/app/components/base/input'
import Toast from '@/app/components/base/toast'
import { emailRegex } from '@/config'
import I18NContext from '@/context/i18n'
import { login } from '@/service/common'
import { encryptPassword } from '@/utils/encryption'
import { resolvePostLoginRedirect } from '../utils/post-login-redirect'
import GreeSSO from '@/app/components/base/chat/chat-with-history/sidebar/gree-sso'
import Cookies from 'js-cookie'

type MailAndPasswordAuthProps = {
  isInvite: boolean
  isEmailSetup: boolean
  allowRegistration: boolean
}

export default function MailAndPasswordAuth({ isInvite, isEmailSetup, allowRegistration: _allowRegistration }: MailAndPasswordAuthProps) {
  const { t } = useTranslation()
  const { locale } = useContext(I18NContext)
  const router = useRouter()
  const searchParams = useSearchParams()
  const [showPassword, setShowPassword] = useState(false)
  const emailFromLink = decodeURIComponent(searchParams.get('email') || '')
  const [email, setEmail] = useState(emailFromLink)
  const [password, setPassword] = useState('')

  const [isLoading, setIsLoading] = useState(false)
  const [showGreeSSO, setShowGreeSSO] = useState(false)
  const pathName = window.location.href
  // const [greeSSOUrl, setGreeSSOUrl] = useState('https://wfserver.gree.com/Sso/Oauth/Show?appID=0347f117-1b67-46a1-b4ec-a173f7bffa14&sourceUrl=' + pathName)
  const [greeSSOUrl, setGreeSSOUrl] = useState('https://wfserver.gree.com/Sso/Oauth/Show?appID=5f4e61c6-29a2-40b2-a62e-c99602dc1f30&sourceUrl=' + pathName)

  const handleEmailPasswordLogin = async () => {
    if (!email) {
      Toast.notify({ type: 'error', message: t('login.error.emailEmpty') })
      return
    }
    if (!emailRegex.test(email)) {
      Toast.notify({
        type: 'error',
        message: t('login.error.emailInValid'),
      })
      return
    }
    if (!password?.trim()) {
      Toast.notify({ type: 'error', message: t('login.error.passwordEmpty') })
      return
    }

    try {
      setIsLoading(true)
      const loginData: Record<string, any> = {
        email,
        password: encryptPassword(password),
        language: locale,
        remember_me: true,
      }
      if (isInvite)
        loginData.invite_token = decodeURIComponent(searchParams.get('invite_token') as string)
      const res = await login({
        url: '/login',
        body: loginData,
      })
      if (res.result === 'success') {
        // Track login success event
        trackEvent('user_login_success', {
          method: 'email_password',
          is_invite: isInvite,
        })

        if (isInvite) {
          router.replace(`/signin/invite-settings?${searchParams.toString()}`)
        }
        else {
          const redirectUrl = resolvePostLoginRedirect(searchParams)
          router.replace(redirectUrl || '/apps')
        }
      }
      else {
        Toast.notify({
          type: 'error',
          message: res.data,
        })
      }
    }
    catch (error) {
      if ((error as ResponseError).code === 'authentication_failed') {
        Toast.notify({
          type: 'error',
          message: t('login.error.invalidEmailOrPassword'),
        })
      }
    }
    finally {
      setIsLoading(false)
    }
  }
  useEffect(() => {
    //1、先清除旧数据
    const gree_mail_tmp = localStorage.getItem('gree_mail')
    const gree_token_tmp = localStorage.getItem('gree_token')

    if (gree_mail_tmp) {
      localStorage.removeItem('gree_mail')
    }
    if (gree_token_tmp) {
      localStorage.removeItem('gree_token')
    }

    // 获取URL参数
    const urlSearchParams = new URLSearchParams(window.location.search);
    // const consoleToken = urlSearchParams.get('console_token');
    // const refreshToken = urlSearchParams.get('refresh_token');
    const loginGreeMail = urlSearchParams.get('gree_mail');
    const loginGreeToken = urlSearchParams.get('gree_token');
    // 单点登录跳转逻辑
    //  window.location.href = `https://wfserver.gree.com/Sso/Oauth/Show?appID=0347f117-1b67-46a1-b4ec-a173f7bffa14&sourceUrl=http://10.23.197.232/signin`
    // 步骤2：验证并存储敏感数据
    if (loginGreeMail && loginGreeToken) {
        // localStorage.setItem('gree_mail', loginGreeMail);
        // localStorage.setItem('gree_token', loginGreeToken);
      
        // 存储到cookie中
        const cookieGreeMail = Cookies.get('gree_mail')
        const cookieGreeToken = Cookies.get('gree_token')
        const cookieGreeArgument = Cookies.get('argument')
        if(!cookieGreeMail){
          Cookies.set("gree_mail",loginGreeMail,{
            path: '/',
            expires: 30,         // 30 天
            secure: true,
            sameSite: 'Lax'
          })
        }
        if(!cookieGreeToken){
          Cookies.set("gree_token",loginGreeToken,{
            path: '/',
            expires: 30,         // 30 天
            secure: true,
            sameSite: 'Lax'
          })
        }
        if(!cookieGreeArgument){
            Cookies.set("argument","Please set the argument in the cookies.",{
              path: '/',
              expires: 30,         // 30 天
              secure: true,
              sameSite: 'Lax'
            })
          }
      // 步骤3：清除 URL 中的敏感参数
      router.replace('/apps');
    } else {
      // const greeSSOUrltmp = 'https://wfserver.gree.com/Sso/Oauth/Show?appID=0347f117-1b67-46a1-b4ec-a173f7bffa14&sourceUrl=' + pathName
      const greeSSOUrltmp = 'https://wfserver.gree.com/Sso/Oauth/Show?appID=5f4e61c6-29a2-40b2-a62e-c99602dc1f30&sourceUrl=' + pathName
      setGreeSSOUrl(greeSSOUrltmp)
      // getIp().then((res: IPStatusResponse) => {
      //const greeSSOUrltmp = 'https://wfserver.gree.com/Sso/Oauth/Show?appID=0347f117-1b67-46a1-b4ec-a173f7bffa14&sourceUrl=http://' + res.ip_address + '/signin'
      // const greeSSOUrltmp = 'https://wfserver.gree.com/Sso/Oauth/Show?appID=0347f117-1b67-46a1-b4ec-a173f7bffa14&sourceUrl=' + pathName
      // setGreeSSOUrl(greeSSOUrltmp)
      // })
      // window.location.href = greeSSOUrl
      setShowGreeSSO(true);
    }

  }, [router]);

  return <div>{showGreeSSO && <GreeSSO openid='' sourceUrl={pathName}></GreeSSO>}</div>
  // return (
  //   <form onSubmit={noop}>
  //     <div className="mb-3">
  //       <label htmlFor="email" className="system-md-semibold my-2 text-text-secondary">
  //         {t('login.email')}
  //       </label>
  //       <div className="mt-1">
  //         <Input
  //           value={email}
  //           onChange={e => setEmail(e.target.value)}
  //           disabled={isInvite}
  //           id="email"
  //           type="email"
  //           autoComplete="email"
  //           placeholder={t('login.emailPlaceholder') || ''}
  //           tabIndex={1}
  //         />
  //       </div>
  //     </div>

  //     <div className="mb-3">
  //       <label htmlFor="password" className="my-2 flex items-center justify-between">
  //         <span className="system-md-semibold text-text-secondary">{t('login.password')}</span>
  //         <Link
  //           href={`/reset-password?${searchParams.toString()}`}
  //           className={`system-xs-regular ${isEmailSetup ? 'text-components-button-secondary-accent-text' : 'pointer-events-none text-components-button-secondary-accent-text-disabled'}`}
  //           tabIndex={isEmailSetup ? 0 : -1}
  //           aria-disabled={!isEmailSetup}
  //         >
  //           {t('login.forget')}
  //         </Link>
  //       </label>
  //       <div className="relative mt-1">
  //         <Input
  //           id="password"
  //           value={password}
  //           onChange={e => setPassword(e.target.value)}
  //           onKeyDown={(e) => {
  //             if (e.key === 'Enter')
  //               handleEmailPasswordLogin()
  //           }}
  //           type={showPassword ? 'text' : 'password'}
  //           autoComplete="current-password"
  //           placeholder={t('login.passwordPlaceholder') || ''}
  //           tabIndex={2}
  //         />
  //         <div className="absolute inset-y-0 right-0 flex items-center">
  //           <Button
  //             type="button"
  //             variant="ghost"
  //             onClick={() => setShowPassword(!showPassword)}
  //           >
  //             {showPassword ? '👀' : '😝'}
  //           </Button>
  //         </div>
  //       </div>
  //     </div>

  //     <div className="mb-2">
  //       <Button
  //         tabIndex={2}
  //         variant="primary"
  //         onClick={handleEmailPasswordLogin}
  //         disabled={isLoading || !email || !password}
  //         className="w-full"
  //       >
  //         {t('login.signBtn')}
  //       </Button>
  //     </div>
  //   </form>
  // )
}
