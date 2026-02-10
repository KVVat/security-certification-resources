#!/bin/bash

# ==============================================================================
# Script Name: apply_patches.sh
# Description: AOSPルートに配置された 'patches' フォルダ内の全パッチを一括適用します。
# Usage:       ./apply_patches.sh
# ==============================================================================

# 適用対象のパッチが入っているディレクトリ名
PATCH_DIR="patches"

# 1. 実行場所の確認
if [ ! -d "$PATCH_DIR" ]; then
    echo "❌ エラー: '$PATCH_DIR' ディレクトリが見つかりません。"
    echo "generate_patches.sh で生成した patches フォルダをこの場所にコピーしてください。"
    exit 1
fi

echo "========================================================"
echo "🛠️  Android 16 Security Patch Applier"
echo "   - Patch Source: $PATCH_DIR/"
echo "   - Target Root:  $(pwd)"
echo "========================================================"

# 2. patches フォルダ内の全 .patch ファイルを探索して適用
#    find でファイルを一つずつ取り出し、アルファベット順にソートして処理
find "$PATCH_DIR" -type f -name "*.patch" | sort | while read patch_file; do

    echo "🔧 適用中: $patch_file"

    # patch コマンドのオプション解説:
    # -p0: パッチファイル内のパス（system/vold/...等）をそのまま使用します
    # -b : 適用前にオリジナルファイルを '.orig' という名前でバックアップします
    # -N : すでに適用済みのパッチ（forward-patch）を検知してスキップします
    # -r -: リジェクトファイルを生成せず、画面に出力します

    patch -p0 -b -N < "$patch_file"

    # 3. 実行結果の確認
    if [ $? -eq 0 ]; then
        echo "   ✅ 正常に適用されました。"
    else
        echo "   ⚠️  適用に失敗したか、既に適用済みです。"
    fi
    echo "--------------------------------------------------------"
done

echo "🎉 全てのパッチ適用処理が完了しました。"