import type { ConversationItem } from '@/models/share'
import {
  RiEditBoxLine,
  RiExpandRightLine,
  RiLayoutLeft2Line,
} from '@remixicon/react'
import {
  useCallback,
  useState,
  useEffect,
} from 'react'
import Cookies from 'js-cookie'
import { useTranslation } from 'react-i18next'
import ActionButton from '@/app/components/base/action-button'
import AppIcon from '@/app/components/base/app-icon'
import Button from '@/app/components/base/button'
import List from '@/app/components/base/chat/chat-with-history/sidebar/list'
import RenameModal from '@/app/components/base/chat/chat-with-history/sidebar/rename-modal'
import Confirm from '@/app/components/base/confirm'
import DifyLogo from '@/app/components/base/logo/dify-logo'
import MenuDropdown from '@/app/components/share/text-generation/menu-dropdown'
import { useGlobalPublicStore } from '@/context/global-public-context'
import { cn } from '@/utils/classnames'
import { useChatWithHistoryContext } from '../context'
import GreeSSO from './gree-sso'
import MenuButton from './menu-button'

type Props = {
  isPanel?: boolean
  panelVisible?: boolean
}

const Sidebar = ({ isPanel, panelVisible }: Props) => {
  const { t } = useTranslation()
  const {
    isInstalledApp,
    appData,
    handleNewConversation,
    pinnedConversationList,
    conversationList,
    currentConversationId,
    handleChangeConversation,
    handlePinConversation,
    handleUnpinConversation,
    conversationRenaming,
    handleRenameConversation,
    handleDeleteConversation,
    sidebarCollapseState,
    handleSidebarCollapse,
    isMobile,
    isResponding,
  } = useChatWithHistoryContext()
  const isSidebarCollapsed = sidebarCollapseState
  const systemFeatures = useGlobalPublicStore(s => s.systemFeatures)
  const [showConfirm, setShowConfirm] = useState<ConversationItem | null>(null)
  const [showRename, setShowRename] = useState<ConversationItem | null>(null)
  const [showGreeSSO, setShowGreeSSO] = useState(false)

  // 步骤1：解析 URL 参数
  const urlsearchParams = new URLSearchParams(window.location.search)
  const greeMail = urlsearchParams.get('gree_mail')
  const greeToken = urlsearchParams.get('gree_token')
  const pathname = window.location.pathname
  const origin = window.location.origin
  const gree_mail = Cookies.get('gree_mail')
  const gree_token = Cookies.get('gree_token')
  const argument = Cookies.get('argument')

  
  if (greeMail && greeToken) {
    // localStorage.setItem('gree_mail', greeMail)
    // localStorage.setItem('gree_token', greeToken)
    if(!gree_mail){
      Cookies.set("gree_mail",greeMail,{
        path: '/',
        expires: 30,         // 30 天
        secure: true,
        sameSite: 'Lax'
      })
    }
  if(!gree_token){
      Cookies.set("gree_token",greeToken,{
        path: '/',
          expires: 30,         // 30 天
          secure: true,
          sameSite: 'Lax'
      })
    }
  if(!argument){
    Cookies.set("argument","Please set the argument in the cookies.",{
      path: '/',
      expires: 30,         // 30 天
      secure: true,
      sameSite: 'Lax'
    })
  }
    window.history.replaceState({}, '', pathname)
    }
  //const gree_mail = localStorage.getItem('gree_mail')
    
  useEffect(() => {
    //const gree_token = localStorage.getItem('gree_token')
    if (!gree_token) {
      setShowGreeSSO(true);
    }
  }, [])


  const handleOperate = useCallback((type: string, item: ConversationItem) => {
    if (type === 'pin')
      handlePinConversation(item.id)

    if (type === 'unpin')
      handleUnpinConversation(item.id)

    if (type === 'delete')
      setShowConfirm(item)

    if (type === 'rename')
      setShowRename(item)
  }, [handlePinConversation, handleUnpinConversation])
  const handleCancelConfirm = useCallback(() => {
    setShowConfirm(null)
  }, [])
  const handleDelete = useCallback(() => {
    if (showConfirm)
      handleDeleteConversation(showConfirm.id, { onSuccess: handleCancelConfirm })
  }, [showConfirm, handleDeleteConversation, handleCancelConfirm])
  const handleCancelRename = useCallback(() => {
    setShowRename(null)
  }, [])
  const handleRename = useCallback((newName: string) => {
    if (showRename)
      handleRenameConversation(showRename.id, newName, { onSuccess: handleCancelRename })
  }, [showRename, handleRenameConversation, handleCancelRename])

  return (
    <div className={cn(
      'flex w-full grow flex-col',
      isPanel && 'rounded-xl border-[0.5px] border-components-panel-border-subtle bg-components-panel-bg shadow-lg',
    )}
    >
      <div className={cn(
        'flex shrink-0 items-center gap-3 p-3 pr-2',
      )}
      >
        <div className="shrink-0">
          <AppIcon
            size="large"
            iconType={appData?.site.icon_type}
            icon={appData?.site.icon}
            background={appData?.site.icon_background}
            imageUrl={appData?.site.icon_url}
          />
        </div>
        <div className={cn('system-md-semibold grow truncate text-text-secondary')}>{appData?.site.title}</div>
        {!isMobile && isSidebarCollapsed && (
          <ActionButton size="l" onClick={() => handleSidebarCollapse(false)}>
            <RiExpandRightLine className="h-[18px] w-[18px]" />
          </ActionButton>
        )}
        {!isMobile && !isSidebarCollapsed && (
          <ActionButton size="l" onClick={() => handleSidebarCollapse(true)}>
            <RiLayoutLeft2Line className="h-[18px] w-[18px]" />
          </ActionButton>
        )}
      </div>
      <div className="shrink-0 px-3 py-4">
        <Button variant="secondary-accent" disabled={isResponding} className="w-full justify-center" onClick={handleNewConversation}>
          <RiEditBoxLine className="mr-1 h-4 w-4" />
          {t('share.chat.newChat')}
        </Button>
      </div>
      <div className="h-0 grow space-y-2 overflow-y-auto px-3 pt-4">
        {/* pinned list */}
        {!!pinnedConversationList.length && (
          <div className="mb-4">
            <List
              isPin
              title={t('share.chat.pinnedTitle') || ''}
              list={pinnedConversationList}
              onChangeConversation={handleChangeConversation}
              onOperate={handleOperate}
              currentConversationId={currentConversationId}
            />
          </div>
        )}
        {!!conversationList.length && (
          <List
            title={(pinnedConversationList.length && t('share.chat.unpinnedTitle')) || ''}
            list={conversationList}
            onChangeConversation={handleChangeConversation}
            onOperate={handleOperate}
            currentConversationId={currentConversationId}
          />
        )}
      </div>

      {/* 左下角单点登录和用户信息按钮 */}
      <div className='shrink-0 p-4'>
        {showGreeSSO && <GreeSSO openid='' sourceUrl={pathname}></GreeSSO>}
        {
          gree_mail && (
            <MenuButton />
          )
        }
      </div>


      <div className="flex shrink-0 items-center justify-between p-3">
        <MenuDropdown
          hideLogout={isInstalledApp}
          placement="top-start"
          data={appData?.site}
          forceClose={isPanel && !panelVisible}
        />
        {/* powered by */}
        {/* <div className="shrink-0">
          {!appData?.custom_config?.remove_webapp_brand && (
            <div className={cn(
              'flex shrink-0 items-center gap-1.5 px-1',
            )}
            >
              <div className="system-2xs-medium-uppercase text-text-tertiary">{t('share.chat.poweredBy')}</div>
              {
                systemFeatures.branding.enabled && systemFeatures.branding.workspace_logo
                  ? <img src={systemFeatures.branding.workspace_logo} alt="logo" className="block h-5 w-auto" />
                  : appData?.custom_config?.replace_webapp_logo
                    ? <img src={`${appData?.custom_config?.replace_webapp_logo}`} alt="logo" className="block h-5 w-auto" />
                    : <DifyLogo size="small" />
              }
            </div>
          )}
        </div> */}
        {!!showConfirm && (
          <Confirm
            title={t('share.chat.deleteConversation.title')}
            content={t('share.chat.deleteConversation.content') || ''}
            isShow
            onCancel={handleCancelConfirm}
            onConfirm={handleDelete}
          />
        )}
        {showRename && (
          <RenameModal
            isShow
            onClose={handleCancelRename}
            saveLoading={conversationRenaming}
            name={showRename?.name || ''}
            onSave={handleRename}
          />
        )}
      </div>
    </div>
  )
}

export default Sidebar
