#!/bin/bash

# ==============================================================================
# Script Name: generate_patches.sh
# Description: AOSP作業ディレクトリ内の変更(.origとの差分)を検出し、
#              このフォルダ内のパッチファイルを一括更新します。
# Location:    niap-cc/KeyTestingPatches/Android16/ に配置してください。
# Usage:       ./generate_patches.sh <AOSP_ROOT_PATH>
# ==============================================================================

# 引数チェック
if [ -z "$1" ]; then
    echo "❌ エラー: AOSPのルートディレクトリを指定してください。"
    echo "使用法: ./generate_patches.sh <AOSPのフルパス>"
    exit 1
fi

# パス設定
AOSP_ROOT=$(realpath "$1")
# スクリプトが存在するディレクトリ（= パッチのルート）
PATCH_REPO_DIR=$(dirname "$(realpath "$0")")

echo "========================================================"
echo "🛡️  Android 16 Security Patch Generator"
echo "   - Project Dir (Patches): $PATCH_REPO_DIR"
echo "   - AOSP Source Dir:       $AOSP_ROOT"
echo "========================================================"

# リポジトリ内の .patch ファイルを探索してループ処理
# パッチファイルが存在する場所 = AOSPのディレクトリ構造 とみなす
find "$PATCH_REPO_DIR" -type f -name "*.patch" | sort | while read patch_file_path; do

    # 1. パッチファイル名から AOSP上の対象ファイルパスを逆算する
    # 例: .../Android16/system/vold/KeyStorage.cpp.patch
    #  -> system/vold/KeyStorage.cpp

    # リポジトリルートからの相対パスを取得
    rel_path="${patch_file_path#$PATCH_REPO_DIR/}"

    # 末尾の .patch を削除して、ソースコードのファイルパスにする
    src_rel_path="${rel_path%.patch}"

    # AOSP上の実ファイルパス
    target_src="$AOSP_ROOT/$src_rel_path"
    target_orig="$target_src.orig"

    echo "🔍 Checking: $src_rel_path"

    # 2. AOSP側に .orig と 編集後のファイルが存在するか確認
    if [[ -f "$target_src" && -f "$target_orig" ]]; then

        # 3. diff を生成して、リポジトリ内のパッチファイルを上書き更新
        # 相対パス表記にするため、AOSPルートから diff を実行する形にする

        # 一時的に現在のパッチ内容を取得（更新前後で比較したい場合などに有効だが今回は直接上書き）

        echo "   ⚡ Generating patch..."

        # 重要: AOSPルートに移動してdiffを取ることで、ヘッダーのパス(system/vold/...)を正しく維持する
        (
            cd "$AOSP_ROOT" || exit
            # -u: Unified format
            # パスはリポジトリの構造に合わせて相対パスで出力
            diff -u "$src_rel_path.orig" "$src_rel_path" > "$patch_file_path"
        )

        if [ $? -eq 0 ] || [ $? -eq 1 ]; then
            echo "   ✅ Updated: $rel_path"
        else
            echo "   ⚠️  Failed to generate diff for $src_rel_path"
        fi

    else
        echo "   ⏭️  Skip: AOSP側に .orig または 対象ファイルが見つかりません。"
        echo "         (一度 apply_patches.sh を実行するか、手動で .orig を作成してください)"
    fi
    echo "--------------------------------------------------------"
done

echo "🎉 全ての処理が完了しました。"