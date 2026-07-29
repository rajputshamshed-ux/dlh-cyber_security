#!/bin/bash
# Script: 12-luks_manager.sh
# Usage: ./12-luks_manager.sh <mode> [arguments]
# Modes: create <size> <name> | open <name> | close <name>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <mode> [arguments]"
    echo ""
    echo "Modes:"
    echo "  create <size> <name>  - Create LUKS volume (size in MB)"
    echo "  open <name>           - Open and mount volume"
    echo "  close <name>          - Unmount and close volume"
    echo ""
    echo "Example:"
    echo "  $0 create 500 test_vol"
    echo "  $0 open test_vol"
    echo "  $0 close test_vol"
    echo ""
    echo "Files:"
    echo "  Image: encrypted_<name>.img"
    echo "  Mount: /mnt/<name>"
    echo "  Device: /dev/mapper/<name>"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script requires root privileges.${NC}"
        echo "Please run with sudo."
        exit 1
    fi
}

create_volume() {
    SIZE=$1
    NAME=$2
    IMAGE="encrypted_${NAME}.img"
    MOUNT="/mnt/${NAME}"
    
    echo -e "${YELLOW}Creating LUKS volume...${NC}"
    echo "Size: ${SIZE}MB"
    echo "Name: ${NAME}"
    echo "Image: ${IMAGE}"
    echo ""
    
    # Check if image already exists
    if [ -f "$IMAGE" ]; then
        echo -e "${RED}Error: Image file $IMAGE already exists.${NC}"
        exit 1
    fi
    
    # Create image file
    echo -e "${YELLOW}[1/6] Creating image file...${NC}"
    dd if=/dev/zero of="$IMAGE" bs=1M count="$SIZE" status=progress
    
    # Format with LUKS
    echo -e "${YELLOW}[2/6] Formatting with LUKS...${NC}"
    cryptsetup luksFormat "$IMAGE"
    
    # Open volume
    echo -e "${YELLOW}[3/6] Opening volume...${NC}"
    cryptsetup luksOpen "$IMAGE" "$NAME"
    
    # Create filesystem
    echo -e "${YELLOW}[4/6] Creating filesystem...${NC}"
    mkfs.ext4 "/dev/mapper/$NAME"
    
    # Create mount point
    echo -e "${YELLOW}[5/6] Creating mount point...${NC}"
    mkdir -p "$MOUNT"
    
    # Mount volume
    echo -e "${YELLOW}[6/6] Mounting volume...${NC}"
    mount "/dev/mapper/$NAME" "$MOUNT"
    
    echo ""
    echo -e "${GREEN}SUCCESS: LUKS volume created and mounted!${NC}"
    echo "  Image: $IMAGE"
    echo "  Device: /dev/mapper/$NAME"
    echo "  Mount: $MOUNT"
    echo ""
    echo "To unmount and close: $0 close $NAME"
}

open_volume() {
    NAME=$1
    IMAGE="encrypted_${NAME}.img"
    MOUNT="/mnt/${NAME}"
    
    echo -e "${YELLOW}Opening LUKS volume...${NC}"
    echo "Name: ${NAME}"
    echo "Image: ${IMAGE}"
    echo ""
    
    # Check if image exists
    if [ ! -f "$IMAGE" ]; then
        echo -e "${RED}Error: Image file $IMAGE not found.${NC}"
        exit 1
    fi
    
    # Check if already open
    if [ -e "/dev/mapper/$NAME" ]; then
        echo -e "${YELLOW}Volume already open.${NC}"
    else
        echo -e "${YELLOW}[1/3] Opening volume...${NC}"
        cryptsetup luksOpen "$IMAGE" "$NAME"
    fi
    
    # Create mount point
    echo -e "${YELLOW}[2/3] Creating mount point...${NC}"
    mkdir -p "$MOUNT"
    
    # Mount volume
    echo -e "${YELLOW}[3/3] Mounting volume...${NC}"
    mount "/dev/mapper/$NAME" "$MOUNT"
    
    echo ""
    echo -e "${GREEN}SUCCESS: Volume mounted at $MOUNT${NC}"
    echo ""
    echo "Contents:"
    ls -la "$MOUNT" | head -10
}

close_volume() {
    NAME=$1
    MOUNT="/mnt/${NAME}"
    
    echo -e "${YELLOW}Closing LUKS volume...${NC}"
    echo "Name: ${NAME}"
    echo ""
    
    # Check if mounted
    if mount | grep -q "/mnt/$NAME"; then
        echo -e "${YELLOW}[1/2] Unmounting volume...${NC}"
        umount "$MOUNT"
    else
        echo -e "${YELLOW}Volume not mounted.${NC}"
    fi
    
    # Check if open
    if [ -e "/dev/mapper/$NAME" ]; then
        echo -e "${YELLOW}[2/2] Closing volume...${NC}"
        cryptsetup luksClose "$NAME"
    else
        echo -e "${YELLOW}Volume not open.${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}SUCCESS: Volume closed.${NC}"
}

# Main script
if [ $# -lt 2 ]; then
    usage
fi

MODE=$1

case "$MODE" in
    create)
        if [ $# -ne 3 ]; then
            echo -e "${RED}Error: create mode requires <size> <name>${NC}"
            usage
        fi
        check_root
        create_volume "$2" "$3"
        ;;
    open)
        if [ $# -ne 2 ]; then
            echo -e "${RED}Error: open mode requires <name>${NC}"
            usage
        fi
        check_root
        open_volume "$2"
        ;;
    close)
        if [ $# -ne 2 ]; then
            echo -e "${RED}Error: close mode requires <name>${NC}"
            usage
        fi
        check_root
        close_volume "$2"
        ;;
    *)
        echo -e "${RED}Error: Unknown mode '$MODE'${NC}"
        usage
        ;;
esac
