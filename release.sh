#!/bin/bash
set -e  # 任何命令失败时退出

# 保存当前分支
ORIGINAL_BRANCH=$(git branch --show-current)

# 错误处理函数
error_handler() {
    echo "❌ 发生错误，正在回退..."
    cleanup
}

cleanup() {
    # 尝试回到原始分支
    git checkout "$ORIGINAL_BRANCH" 2>/dev/null || true
    # 如果有stash，尝试恢复
    if git stash list | grep -q "stash@{0}"; then
        git stash pop 2>/dev/null || echo "⚠️  无法恢复stash，请手动执行 git stash pop"
    fi
    exit 1
}

# 设置错误时的trap
trap error_handler ERR

echo "📥 正在拉取远程更新..."
git fetch -p

echo "💾 正在保存本地更改..."
git stash

echo "🔀 正在切换到 release 分支..."
git checkout release

echo "🔄 正在 rebase master..."
git rebase master

echo "📤 正在推送到远程..."
git push

echo "♻️  正在恢复本地更改..."
git stash pop||true

echo "✅ 操作成功完成！恢复初始状态"
cleanup