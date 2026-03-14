'use client'
import type { FC } from 'react'
import type { Emoji, WorkflowToolProviderOutputParameter, WorkflowToolProviderParameter, WorkflowToolProviderRequest } from '../types'
import { RiErrorWarningLine } from '@remixicon/react'
import { produce } from 'immer'
import * as React from 'react'
import { useMemo, useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import AppIcon from '@/app/components/base/app-icon'
import Button from '@/app/components/base/button'
import Drawer from '@/app/components/base/drawer-plus'
import EmojiPicker from '@/app/components/base/emoji-picker'
import Input from '@/app/components/base/input'
import Textarea from '@/app/components/base/textarea'
import Toast from '@/app/components/base/toast'
import Tooltip from '@/app/components/base/tooltip'
import LabelSelector from '@/app/components/tools/labels/selector'
import ConfirmModal from '@/app/components/tools/workflow-tool/confirm-modal'
import MethodSelector from '@/app/components/tools/workflow-tool/method-selector'
import { VarType } from '@/app/components/workflow/types'
import { cn } from '@/utils/classnames'
import { buildWorkflowOutputParameters } from './utils'
import { RiArrowDownSLine } from '@remixicon/react'
import { useDebounceFn } from 'ahooks'
import Checkbox from '@/app/components/base/checkbox'
import {
  PortalToFollowElem,
  PortalToFollowElemContent,
  PortalToFollowElemTrigger,
} from '@/app/components/base/portal-to-follow-elem'

type Props = {
  isAdd?: boolean
  payload: any
  onHide: () => void
  onRemove?: () => void
  onCreate?: (payload: WorkflowToolProviderRequest & { workflow_app_id: string }) => void
  onSave?: (payload: WorkflowToolProviderRequest & Partial<{
    workflow_app_id: string
    workflow_tool_id: string
  }>) => void
}
// Add and Edit
const WorkflowToolAsModal: FC<Props> = ({
  isAdd,
  payload,
  onHide,
  onRemove,
  onSave,
  onCreate,
}) => {
  const { t } = useTranslation()

  const [showEmojiPicker, setShowEmojiPicker] = useState<boolean>(false)
  const [emoji, setEmoji] = useState<Emoji>(payload.icon)
  const [label, setLabel] = useState<string>(payload.label)
  const [name, setName] = useState(payload.name)
  const [description, setDescription] = useState(payload.description)
  const [parameters, setParameters] = useState<WorkflowToolProviderParameter[]>(payload.parameters)
  const rawOutputParameters = payload.outputParameters
  const outputSchema = payload.tool?.output_schema
  const outputParameters = useMemo<WorkflowToolProviderOutputParameter[]>(() => buildWorkflowOutputParameters(rawOutputParameters, outputSchema), [rawOutputParameters, outputSchema])
  const reservedOutputParameters: WorkflowToolProviderOutputParameter[] = [
    {
      name: 'text',
      description: t('workflow.nodes.tool.outputVars.text'),
      type: VarType.string,
      reserved: true,
    },
    {
      name: 'files',
      description: t('workflow.nodes.tool.outputVars.files.title'),
      type: VarType.arrayFile,
      reserved: true,
    },
    {
      name: 'json',
      description: t('workflow.nodes.tool.outputVars.json'),
      type: VarType.arrayObject,
      reserved: true,
    },
  ]
  
  // 动态获取组织架构树数据
  const [organizationTree, setOrganizationTree] = useState<any[]>([])
  const [loadingOrg, setLoadingOrg] = useState(false)
  
  // 获取组织架构数据
  useEffect(() => {
    const fetchOrganizations = async () => {
      try {
        setLoadingOrg(true)
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_PREFIX}/organizations/organizations`)
        const result = await response.json()
        
        if (result.success) {
          setOrganizationTree(result.data)
        } else {
          console.error('获取组织架构失败:', result.message)
          Toast.notify({
            type: 'error',
            message: '获取组织架构失败',
          })
        }
      } catch (error) {
        console.error('获取组织架构出错:', error)
        Toast.notify({
          type: 'error',
          message: '获取组织架构出错',
        })
      } finally {
        setLoadingOrg(false)
      }
    }
    
    fetchOrganizations()
  }, [])
  
  // 下拉框展开状态
  const [open, setOpen] = useState(false)
  // 搜索关键词
  const [keywords, setKeywords] = useState('')
  const [searchKeywords, setSearchKeywords] = useState('')
  const { run: handleSearch } = useDebounceFn(() => {
    setSearchKeywords(keywords)
  }, { wait: 500 })
  const handleKeywordsChange = (value: string) => {
    setKeywords(value)
    handleSearch()
  }
  
  // 递归获取所有第三级组织ID
  const getAllThirdLevelOrgIds = (node: any): string[] => {
    if (!node.children || node.children.length === 0) {
      return [node.id]
    }
    let ids: string[] = []
    node.children.forEach((child: any) => {
      ids = [...ids, ...getAllThirdLevelOrgIds(child)]
    })
    return ids
  }
  
  // 处理组织选择
  const handleOrgSelect = (orgId: string) => {
    const selectedNode = findNodeById(organizationTree, orgId)
    if (!selectedNode) return
    
    const thirdLevelIds = getAllThirdLevelOrgIds(selectedNode)
    
    setSelectedOrgIds(prev => {
      // 检查是否所有第三级节点都已选中
      const allSelected = thirdLevelIds.every(id => prev.includes(id))
      
      if (allSelected) {
        // 取消选择所有第三级节点
        return prev.filter(id => !thirdLevelIds.includes(id))
      } else {
        // 选择所有第三级节点
        const newIds = [...prev]
        thirdLevelIds.forEach(id => {
          if (!newIds.includes(id)) {
            newIds.push(id)
          }
        })
        return newIds
      }
    })
  }
  
  // 根据ID查找节点
  const findNodeById = (nodes: any[], id: string): any => {
    for (const node of nodes) {
      if (node.id === id) {
        return node
      }
      if (node.children) {
        const found = findNodeById(node.children, id)
        if (found) {
          return found
        }
      }
    }
    return null
  }
  
  // 检查节点是否被选择
  const isNodeSelected = (node: any): boolean => {
    // 如果节点没有子节点，直接检查该节点的ID是否在selectedOrgIds中
    if (!node.children || node.children.length === 0) {
      const isSelected = selectedOrgIds.includes(node.id)
      return isSelected
    }
    
    // 如果有子节点，检查所有子节点是否都被选择
    const thirdLevelIds = getAllThirdLevelOrgIds(node)
    const isSelected = thirdLevelIds.every(id => selectedOrgIds.includes(id))
    return isSelected
  }
  
  // 过滤节点
  const filterNodes = (nodes: any[]): any[] => {
    if (!searchKeywords) return nodes
    
    return nodes.filter(node => {
      // 检查当前节点是否匹配
      const nodeMatches = node.name.toLowerCase().includes(searchKeywords.toLowerCase())
      
      // 检查子节点是否匹配
      if (node.children && node.children.length > 0) {
        const filteredChildren = filterNodes(node.children)
        if (filteredChildren.length > 0) {
          return true
        }
      }
      
      return nodeMatches
    })
  }
  
  // 递归渲染组织架构树
  const renderOrganizationTree = (nodes: any[], level: number = 0) => {
    const filteredNodes = filterNodes(nodes)
    
    return filteredNodes.map(node => {
      const isSelected = isNodeSelected(node)
      
      return (
        <div key={node.id} className="py-1">
          <div className="flex items-center">
            <Checkbox
              className="shrink-0"
              checked={isSelected}
              onCheck={() => handleOrgSelect(node.id)}
            />
            <div style={{ marginLeft: `${level * 16}px` }} className="text-sm leading-5 text-text-secondary">{node.name}</div>
          </div>
          {node.children && node.children.length > 0 && (
            <div className="mt-1 pl-6">
              {renderOrganizationTree(node.children, level + 1)}
            </div>
          )}
        </div>
      )
    })
  }

  const handleParameterChange = (key: string, value: any, index: number) => {
    const newData = produce(parameters, (draft: WorkflowToolProviderParameter[]) => {
      if (key === 'description')
        draft[index].description = value
      else
        draft[index].form = value
    })
    setParameters(newData)
  }
  const [labels, setLabels] = useState<string[]>(payload.labels)
  const handleLabelSelect = (value: string[]) => {
    setLabels(value)
  }
  const [privacyPolicy, setPrivacyPolicy] = useState(payload.privacy_policy)
  const [showModal, setShowModal] = useState(false)
  
  // 存储选择的组织ID，直接从payload中初始化
  const [selectedOrgIds, setSelectedOrgIds] = useState<string[]>([])
  
  // 组件挂载时初始化selectedOrgIds
  useEffect(() => {
    console.log('=== 组件挂载初始化 ===')
    console.log('完整payload:', JSON.stringify(payload, null, 2))
    console.log('payload.visible_org_ids:', payload.visible_org_ids)
    console.log('payload.visible_org_ids类型:', typeof payload.visible_org_ids)
    console.log('payload.visible_org_ids长度:', payload.visible_org_ids?.length)
    if (payload.visible_org_ids && Array.isArray(payload.visible_org_ids) && payload.visible_org_ids.length > 0) {
      console.log('初始化selectedOrgIds:', payload.visible_org_ids)
      setSelectedOrgIds(payload.visible_org_ids)
    } else {
      console.log('payload.visible_org_ids为空或不是数组')
    }
  }, []) // 只在组件挂载时执行一次
  
  // 调试日志
  useEffect(() => {
    console.log('=== 状态更新 ===')
    console.log('selectedOrgIds:', selectedOrgIds)
    console.log('organizationTree length:', organizationTree.length)
  }, [selectedOrgIds, organizationTree])

  const isNameValid = (name: string) => {
    // when the user has not input anything, no need for a warning
    if (name === '')
      return true

    return /^\w+$/.test(name)
  }

  const isOutputParameterReserved = (name: string) => {
    return reservedOutputParameters.find(p => p.name === name)
  }

  const onConfirm = () => {
    let errorMessage = ''
    if (!label)
      errorMessage = t('common.errorMsg.fieldRequired', { field: t('tools.createTool.name') })

    if (!name)
      errorMessage = t('common.errorMsg.fieldRequired', { field: t('tools.createTool.nameForToolCall') })

    if (!isNameValid(name))
      errorMessage = t('tools.createTool.nameForToolCall') + t('tools.createTool.nameForToolCallTip')

    if (errorMessage) {
      Toast.notify({
        type: 'error',
        message: errorMessage,
      })
      return
    }

    // 获取所有选中的第三级组织ID（已经是第三级了，但确保格式正确）
    const visibleOrgIds = selectedOrgIds.filter(id => {
      // 验证ID是否存在于组织架构树中且是第三级
      const node = findNodeById(organizationTree, id)
      return node && (!node.children || node.children.length === 0)
    })
    // 验证这个可见权限不能为空
    if (visibleOrgIds.length === 0) {
      Toast.notify({
        type: 'error',
        message: '可见权限不能为空',
      })
      return
    }
    
    const requestParams = {
      name,
      description,
      icon: emoji,
      label,
      parameters: parameters.map(item => ({
        name: item.name,
        description: item.description,
        form: item.form,
      })),
      labels,
      privacy_policy: privacyPolicy,
      visible_org_ids: visibleOrgIds,
    }
    
    // 打印请求参数到控制台
    console.log('请求参数:', requestParams)
    console.log('选择的第三级组织ID数组:', visibleOrgIds)
    
    if (!isAdd) {
      // 打印出requestParams
      console.log('更新请求参数:', requestParams)
      onSave?.({
        ...requestParams,
        workflow_tool_id: payload.workflow_tool_id,
      })
    }
    else {
      // 打印出requestParams
      console.log('创建请求参数:', requestParams)
      onCreate?.({
        ...requestParams,
        workflow_app_id: payload.workflow_app_id,
      })
    }
  }

  return (
    <>
      <Drawer
        isShow
        onHide={onHide}
        title={t('workflow.common.workflowAsTool')!}
        panelClassName="mt-2 !w-[640px]"
        maxWidthClassName="!max-w-[640px]"
        height="calc(100vh - 16px)"
        headerClassName="!border-b-divider"
        body={(
          <div className="flex h-full flex-col">
            <div className="h-0 grow space-y-4 overflow-y-auto px-6 py-3">
              {/* name & icon */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">
                  {t('tools.createTool.name')}
                  {' '}
                  <span className="ml-1 text-red-500">*</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <AppIcon size="large" onClick={() => { setShowEmojiPicker(true) }} className="cursor-pointer" iconType="emoji" icon={emoji.content} background={emoji.background} />
                  <Input
                    className="h-10 grow"
                    placeholder={t('tools.createTool.toolNamePlaceHolder')!}
                    value={label}
                    onChange={e => setLabel(e.target.value)}
                  />
                </div>
              </div>
              {/* name for tool call */}
              <div>
                <div className="system-sm-medium flex items-center py-2 text-text-primary">
                  {t('tools.createTool.nameForToolCall')}
                  {' '}
                  <span className="ml-1 text-red-500">*</span>
                  <Tooltip
                    popupContent={(
                      <div className="w-[180px]">
                        {t('tools.createTool.nameForToolCallPlaceHolder')}
                      </div>
                    )}
                  />
                </div>
                <Input
                  className="h-10"
                  placeholder={t('tools.createTool.nameForToolCallPlaceHolder')!}
                  value={name}
                  onChange={e => setName(e.target.value)}
                />
                {!isNameValid(name) && (
                  <div className="text-xs leading-[18px] text-red-500">{t('tools.createTool.nameForToolCallTip')}</div>
                )}
              </div>
              {/* description */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">{t('tools.createTool.description')}</div>
                <Textarea
                  placeholder={t('tools.createTool.descriptionPlaceholder') || ''}
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                />
              </div>
              {/* Tool Input  */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">{t('tools.createTool.toolInput.title')}</div>
                <div className="w-full overflow-x-auto rounded-lg border border-divider-regular">
                  <table className="w-full text-xs font-normal leading-[18px] text-text-secondary">
                    <thead className="uppercase text-text-tertiary">
                      <tr className="border-b border-divider-regular">
                        <th className="w-[156px] p-2 pl-3 font-medium">{t('tools.createTool.toolInput.name')}</th>
                        <th className="w-[102px] p-2 pl-3 font-medium">{t('tools.createTool.toolInput.method')}</th>
                        <th className="p-2 pl-3 font-medium">{t('tools.createTool.toolInput.description')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {parameters.map((item, index) => (
                        <tr key={index} className="border-b border-divider-regular last:border-0">
                          <td className="max-w-[156px] p-2 pl-3">
                            <div className="text-[13px] leading-[18px]">
                              <div title={item.name} className="flex">
                                <span className="truncate font-medium text-text-primary">{item.name}</span>
                                <span className="shrink-0 pl-1 text-xs leading-[18px] text-[#ec4a0a]">{item.required ? t('tools.createTool.toolInput.required') : ''}</span>
                              </div>
                              <div className="text-text-tertiary">{item.type}</div>
                            </div>
                          </td>
                          <td>
                            {item.name === '__image' && (
                              <div className={cn(
                                'flex h-9 min-h-[56px] cursor-default items-center gap-1 bg-transparent px-3 py-2',
                              )}
                              >
                                <div className={cn('grow truncate text-[13px] leading-[18px] text-text-secondary')}>
                                  {t('tools.createTool.toolInput.methodParameter')}
                                </div>
                              </div>
                            )}
                            {item.name !== '__image' && (
                              <MethodSelector value={item.form} onChange={value => handleParameterChange('form', value, index)} />
                            )}
                          </td>
                          <td className="w-[236px] p-2 pl-3 text-text-tertiary">
                            <input
                              type="text"
                              className="w-full appearance-none bg-transparent text-[13px] font-normal leading-[18px] text-text-secondary caret-primary-600 outline-none placeholder:text-text-quaternary"
                              placeholder={t('tools.createTool.toolInput.descriptionPlaceholder')!}
                              value={item.description}
                              onChange={e => handleParameterChange('description', e.target.value, index)}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              {/* 可见权限 */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">可见权限</div>
                <div className="relative">
                  <PortalToFollowElem
                    open={open}
                    onOpenChange={setOpen}
                    placement="bottom-start"
                    offset={4}
                  >
                    <PortalToFollowElemTrigger
                      onClick={() => setOpen(v => !v)}
                      className="block"
                    >
                      <div className={cn(
                        'flex h-10 cursor-pointer items-center gap-1 rounded-lg border-[0.5px] border-transparent bg-components-input-bg-normal px-3 hover:bg-components-input-bg-hover',
                        open && '!hover:bg-components-input-bg-hover hover:bg-components-input-bg-hover',
                      )}
                      >
                        <div className="grow truncate text-[13px] leading-[18px] text-text-quaternary">
                          {loadingOrg ? '加载中...' : selectedOrgIds.length > 0 ? `已选择 ${selectedOrgIds.length} 个部门` : '选择可见部门'}
                        </div>
                        <div className="ml-1 shrink-0 text-text-secondary opacity-60">
                          <RiArrowDownSLine className="h-4 w-4" />
                        </div>
                      </div>
                    </PortalToFollowElemTrigger>
                    <PortalToFollowElemContent className="z-[1040]">
                      <div className="relative w-[591px] rounded-lg border-[0.5px] border-components-panel-border bg-components-panel-bg-blur shadow-lg  backdrop-blur-[5px]">
                        <div className="border-b-[0.5px] border-divider-regular p-2">
                          <Input
                            showLeftIcon
                            showClearIcon
                            value={keywords}
                            onChange={e => handleKeywordsChange(e.target.value)}
                            onClear={() => handleKeywordsChange('')}
                          />
                        </div>
                        <div className="max-h-[264px] overflow-y-auto p-1">
                          {loadingOrg ? (
                            <div className="flex items-center justify-center py-8 text-text-tertiary">
                              加载组织架构中...
                            </div>
                          ) : organizationTree.length > 0 ? (
                            renderOrganizationTree(organizationTree)
                          ) : (
                            <div className="flex items-center justify-center py-8 text-text-tertiary">
                              暂无组织架构数据
                            </div>
                          )}
                        </div>
                      </div>
                    </PortalToFollowElemContent>
                  </PortalToFollowElem>
                </div>
              </div>
              {/* Tool Output  */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">{t('tools.createTool.toolOutput.title')}</div>
                <div className="w-full overflow-x-auto rounded-lg border border-divider-regular">
                  <table className="w-full text-xs font-normal leading-[18px] text-text-secondary">
                    <thead className="uppercase text-text-tertiary">
                      <tr className="border-b border-divider-regular">
                        <th className="w-[156px] p-2 pl-3 font-medium">{t('tools.createTool.name')}</th>
                        <th className="p-2 pl-3 font-medium">{t('tools.createTool.toolOutput.description')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...reservedOutputParameters, ...outputParameters].map((item, index) => (
                        <tr key={index} className="border-b border-divider-regular last:border-0">
                          <td className="max-w-[156px] p-2 pl-3">
                            <div className="text-[13px] leading-[18px]">
                              <div title={item.name} className="flex items-center">
                                <span className="truncate font-medium text-text-primary">{item.name}</span>
                                <span className="shrink-0 pl-1 text-xs leading-[18px] text-[#ec4a0a]">{item.reserved ? t('tools.createTool.toolOutput.reserved') : ''}</span>
                                {
                                  !item.reserved && isOutputParameterReserved(item.name)
                                    ? (
                                        <Tooltip
                                          popupContent={(
                                            <div className="w-[180px]">
                                              {t('tools.createTool.toolOutput.reservedParameterDuplicateTip')}
                                            </div>
                                          )}
                                        >
                                          <RiErrorWarningLine className="h-3 w-3 text-text-warning-secondary" />
                                        </Tooltip>
                                      )
                                    : null
                                }
                              </div>
                              <div className="text-text-tertiary">{item.type}</div>
                            </div>
                          </td>
                          <td className="w-[236px] p-2 pl-3 text-text-tertiary">
                            <span className="text-[13px] font-normal leading-[18px] text-text-secondary">{item.description}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              {/* Tags */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">{t('tools.createTool.toolInput.label')}</div>
                <LabelSelector value={labels} onChange={handleLabelSelect} />
              </div>
              {/* Privacy Policy */}
              <div>
                <div className="system-sm-medium py-2 text-text-primary">{t('tools.createTool.privacyPolicy')}</div>
                <Input
                  className="h-10"
                  value={privacyPolicy}
                  onChange={e => setPrivacyPolicy(e.target.value)}
                  placeholder={t('tools.createTool.privacyPolicyPlaceholder') || ''}
                />
              </div>
            </div>
            <div className={cn((!isAdd && onRemove) ? 'justify-between' : 'justify-end', 'mt-2 flex shrink-0 rounded-b-[10px] border-t border-divider-regular bg-background-section-burn px-6 py-4')}>
              {!isAdd && onRemove && (
                <Button variant="warning" onClick={onRemove}>{t('common.operation.delete')}</Button>
              )}
              <div className="flex space-x-2 ">
                <Button onClick={onHide}>{t('common.operation.cancel')}</Button>
                <Button
                  variant="primary"
                  onClick={() => {
                    if (isAdd)
                      onConfirm()
                    else
                      setShowModal(true)
                  }}
                >
                  {t('common.operation.save')}
                </Button>
              </div>
            </div>
          </div>
        )}
        isShowMask={true}
        clickOutsideNotOpen={true}
      />
      {showEmojiPicker && (
        <EmojiPicker
          onSelect={(icon, icon_background) => {
            setEmoji({ content: icon, background: icon_background })
            setShowEmojiPicker(false)
          }}
          onClose={() => {
            setShowEmojiPicker(false)
          }}
        />
      )}
      {showModal && (
        <ConfirmModal
          show={showModal}
          onClose={() => setShowModal(false)}
          onConfirm={onConfirm}
        />
      )}
    </>

  )
}
export default React.memo(WorkflowToolAsModal)
