#!/usr/bin/env python3
"""
调用本地插件批量上传接口
"""
import argparse
import sys

import requests


def upload_local_plugins(api_base_url: str, authorization_token: str):
    """
    调用本地插件批量上传接口

    Args:
        api_base_url: API 基础地址，例如 http://localhost:5001
        authorization_token: 授权 Token
    """
    url = f"{api_base_url}/console/api/workspaces/current/plugin/upload/pkg/local"

    headers = {
        "Authorization": f"Bearer {authorization_token}",
        "Content-Type": "application/json"
    }

    try:
        print(f"正在调用接口: {url}")
        print("-" * 50)

        response = requests.post(url, headers=headers, timeout=300)

        if response.status_code == 200:
            result = response.json()
            print(f"✅ 上传完成!")
            print(f"   总计文件: {result.get('total', 0)}")
            print(f"   成功: {result.get('success', 0)}")
            print(f"   失败: {result.get('failed', 0)}")
            print("-" * 50)

            if result.get('results'):
                print("\n成功上传的文件:")
                for item in result['results']:
                    print(f"  ✓ {item['filename']}")

            if result.get('errors'):
                print("\n上传失败的文件:")
                for error in result['errors']:
                    print(f"  ✗ {error}")

            return True
        else:
            print(f"❌ 请求失败: HTTP {response.status_code}")
            try:
                error_data = response.json()
                print(f"错误信息: {error_data}")
            except:
                print(f"响应内容: {response.text}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"❌ 连接失败: 无法连接到 {api_base_url}")
        print("请检查:")
        print("  1. 后端服务是否已启动")
        print("  2. 地址和端口是否正确")
        return False
    except requests.exceptions.Timeout:
        print(f"❌ 请求超时")
        return False
    except Exception as e:
        print(f"❌ 发生错误: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description='批量上传本地插件')
    parser.add_argument(
        '--url',
        default='http://localhost:5001',
        help='API 基础地址 (默认: http://localhost:5001)'
    )
    parser.add_argument(
        '--token',
        required=True,
        help='授权 Token (Bearer Token)'
    )

    args = parser.parse_args()

    success = upload_local_plugins(args.url, args.token)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
