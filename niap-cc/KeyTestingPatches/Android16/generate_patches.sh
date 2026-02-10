#!/bin/bash

# ==============================================================================
# Script Name: generate_patches.sh
# Description: AOSP作業ディレクトリ内の変更(.origとの差分)を検出し、
#              このフォルダ内の 'patches' ディレクトリ以下に構造を維持して生成します。
# Location:    niap-cc/KeyTestingPatches/Android16/ に配置してください。
# Usage:       ./generate_patches.sh <AOSP_ROOT_PATH>
# ==============================================================================

# 1. 引数チェック
if [ -z "$1" ]; then
    echo "❌ エラー: AOSPのルートディレクトリを指定してください。"
    echo "使用法: ./generate_patches.sh <AOSPのフルパス>"
    exit 1
fi

# 2. パス設定
AOSP_ROOT=$(realpath "$1")
# スクリプトが存在するディレクトリ（= リポジトリ上のパッチルート）
REPO_PATCH_ROOT=$(dirname "$(realpath "$0")")
# 出力先ディレクトリ (一時保存用)
OUTPUT_DIR="$REPO_PATCH_ROOT/patches"

echo "========================================================"
echo "🛡️  Android 16 Security Patch Generator (Staging Mode)"
echo "   - Repo Patch Dir:  $REPO_PATCH_ROOT"
echo "   - Output Dir:      $OUTPUT_DIR"
echo "   - AOSP Source Dir: $AOSP_ROOT"
echo "========================================================"

# 出力先ディレクトリの作成（なければ）
mkdir -p "$OUTPUT_DIR"

# 3. リポジトリ内の .patch ファイルを探索（patchesフォルダ自体は除外）
#    -path "$OUTPUT_DIR" -prune で出力先フォルダ内の再帰検索を防止
find "$REPO_PATCH_ROOT" -path "$OUTPUT_DIR" -prune -o -type f -name "*.patch" -print | sort | while read template_patch_path; do

    # リポジトリルートからの相対パスを取得 (例: system/vold/KeyStorage.cpp.patch)
    rel_path="${template_patch_path#$REPO_PATCH_ROOT/}"

    # 出力先のフルパスを決定
    dest_patch_path="$OUTPUT_DIR/$rel_path"

    # パッチファイル名から AOSP上の対象ファイルパスを逆算
    src_rel_path="${rel_path%.patch}"

    # AOSP上の実ファイルパス
    target_src="$AOSP_ROOT/$src_rel_path"
    target_orig="$target_src.orig"

    echo "🔍 Checking: $src_rel_path"

    # 4. AOSP側に .orig と 編集後のファイルが存在するか確認
    if [[ -f "$target_src" && -f "$target_orig" ]]; then

        # 出力先のサブディレクトリ構造を作成 (例: patches/system/vold/)
        mkdir -p "$(dirname "$dest_patch_path")"

        echo "   ⚡ Generating patch to staging area..."

        # 5. diff を生成
        (
            cd "$AOSP_ROOT" || exit
            # -u: Unified format
            # パスはリポジトリの構造に合わせて相対パスで出力
            diff -u "$src_rel_path.orig" "$src_rel_path" > "$dest_patch_path"
        )

        if [ $? -eq 0 ] || [ $? -eq 1 ]; then
            echo "   ✅ Generated: patches/$rel_path"
        else
            echo "   ⚠️  Failed to generate diff for $src_rel_path"
        fi

    else
        echo "   ⏭️  Skip: AOSP側に .orig または 対象ファイルが見つかりません。"
    fi
    echo "--------------------------------------------------------"
done

echo "🎉 全ての処理が完了しました。"
echo "📁 出力先: $OUTPUT_DIR"