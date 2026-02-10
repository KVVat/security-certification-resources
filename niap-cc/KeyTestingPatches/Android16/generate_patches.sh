#!/bin/bash

# ==============================================================================
# Script Name: generate_patches.sh
# Description: Detects changes (differences from .orig) in the AOSP working directory,
#              and generates them in the 'patches' directory within this folder, maintaining the structure.
# Location:    Place in niap-cc/KeyTestingPatches/Android16/.
# Usage:       ./generate_patches.sh <AOSP_ROOT_PATH>
# ==============================================================================

# 1. Argument check
if [ -z "$1" ]; then
    echo "❌ Error: Please specify the AOSP root directory."
    echo "Usage: ./generate_patches.sh <AOSP_FULL_PATH>"
    exit 1
fi

# 2. Path settings
AOSP_ROOT=$(realpath "$1")
# Directory where the script exists (= patch root on the repository)
REPO_PATCH_ROOT=$(dirname "$(realpath "$0")")
# Output directory (for temporary storage)
OUTPUT_DIR="$REPO_PATCH_ROOT/patches"

echo "========================================================"
echo "🛡️  Android 16 Security Patch Generator (Staging Mode)"
echo "   - Repo Patch Dir:  $REPO_PATCH_ROOT"
echo "   - Output Dir:      $OUTPUT_DIR"
echo "   - AOSP Source Dir: $AOSP_ROOT"
echo "========================================================"

# Create output directory (if it doesn't exist)
mkdir -p "$OUTPUT_DIR"

# 3. Search for .patch files in the repository (excluding the patches folder itself)
#    -path "$OUTPUT_DIR" -prune prevents recursive search within the output folder
find "$REPO_PATCH_ROOT" -path "$OUTPUT_DIR" -prune -o -type f -name "*.patch" -print | sort | while read template_patch_path; do

    # Get the relative path from the repository root (e.g., system/vold/KeyStorage.cpp.patch)
    rel_path="${template_patch_path#$REPO_PATCH_ROOT/}"

    # Determine the full path of the output destination
    dest_patch_path="$OUTPUT_DIR/$rel_path"

    # Infer the target file path on AOSP from the patch file name
    src_rel_path="${rel_path%.patch}"

    # Actual file path on AOSP
    target_src="$AOSP_ROOT/$src_rel_path"
    target_orig="$target_src.orig"

    echo "🔍 Checking: $src_rel_path"

    # 4. Check if .orig and the modified file exist on the AOSP side
    if [[ -f "$target_src" && -f "$target_orig" ]]; then

        # Create the subdirectory structure of the output destination (e.g., patches/system/vold/)
        mkdir -p "$(dirname "$dest_patch_path")"

        echo "   ⚡ Generating patch to staging area..."

        # 5. Generate diff
        (
            cd "$AOSP_ROOT" || exit
            # -u: Unified format
            # Output paths are relative to match the repository structure
            diff -u "$src_rel_path.orig" "$src_rel_path" > "$dest_patch_path"
        )

        if [ $? -eq 0 ] || [ $? -eq 1 ]; then
            echo "   ✅ Generated: patches/$rel_path"
        else
            echo "   ⚠️  Failed to generate diff for $src_rel_path"
        fi

    else
        echo "   ⏭️  Skip: .orig or target file not found on the AOSP side."
    fi
    echo "--------------------------------------------------------"
done

echo "🎉 All processes have been completed."
echo "📁 Output destination: $OUTPUT_DIR"
