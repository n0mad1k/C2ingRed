#!/bin/bash

# Default configurations
DEFAULT_IMAGE_FILTER="*kali-last-snapshot*"
DEFAULT_OWNER_ID="679593333241"
DEFAULT_REGION="us-east-1"

# Debugging flag
DEBUG=false

# Usage function
function usage() {
    echo "Usage: $0 [--image-filter <filter>] [--owner-id <owner-id>] [--debug] [--help]"
    echo ""
    echo "Options:"
    echo "  --image-filter <filter>  Filter for AMI names (default: '${DEFAULT_IMAGE_FILTER}')."
    echo "  --owner-id <owner-id>    Owner ID for filtering AMIs (default: '${DEFAULT_OWNER_ID}')."
    echo "  --debug                  Enable verbose debugging."
    echo "  --help                   Display this help message."
    exit 1
}

# Parse arguments
IMAGE_FILTER="$DEFAULT_IMAGE_FILTER"
OWNER_ID="$DEFAULT_OWNER_ID"

while [[ $# -gt 0 ]]; do
    case $1 in
        --image-filter)
            IMAGE_FILTER="$2"
            shift 2
            ;;
        --owner-id)
            OWNER_ID="$2"
            shift 2
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if $DEBUG; then
    echo "DEBUG: Using image filter: $IMAGE_FILTER"
    echo "DEBUG: Using owner ID: $OWNER_ID"
fi

# Step 1: Fetch all AMIs in the default region to identify the latest version
LATEST_AMI=""
LATEST_YEAR=0
LATEST_VERSION=0

AMI_LIST=$(aws ec2 describe-images \
    --region "$DEFAULT_REGION" \
    --filters "Name=name,Values=$IMAGE_FILTER" "Name=owner-id,Values=$OWNER_ID" \
    --query "Images[].[Name]" \
    --output text)

if $DEBUG; then
    echo "DEBUG: AMI list in $DEFAULT_REGION: $AMI_LIST"
fi

for AMI_NAME in $AMI_LIST; do
    if [[ $AMI_NAME != *"-prod-"* ]]; then
        # Extract year and version using regex
        if [[ $AMI_NAME =~ ([0-9]{4})\.([0-9]+)\.([0-9]+) ]]; then
            YEAR=${BASH_REMATCH[1]}
            VERSION=${BASH_REMATCH[2]}

            if $DEBUG; then
                echo "DEBUG: Checking AMI: $AMI_NAME (Year: $YEAR, Version: $VERSION)"
            fi

            if (( YEAR > LATEST_YEAR )) || (( YEAR == LATEST_YEAR && VERSION > LATEST_VERSION )); then
                LATEST_AMI="$AMI_NAME"
                LATEST_YEAR=$YEAR
                LATEST_VERSION=$VERSION
            fi
        fi
    fi
done

if $DEBUG; then
    echo "DEBUG: Latest AMI determined: $LATEST_AMI"
fi

# Step 2: Use the latest AMI name to filter across all regions
if [[ -z "$LATEST_AMI" ]]; then
    echo "No valid AMIs found matching the criteria."
    exit 1
fi

IMAGE_FILTER_LATEST="${LATEST_AMI%-*}*" # Strip the region-specific suffix and add a wildcard

if $DEBUG; then
    echo "DEBUG: Using refined image filter: $IMAGE_FILTER_LATEST"
fi

# Step 3: Fetch AMIs across all regions
REGIONS=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)

echo "Fetching AMIs with filter '$IMAGE_FILTER_LATEST' and owner ID '$OWNER_ID'..."

AMI_MAP=""
REGION_LIST=()

for REGION in $REGIONS; do
    if $DEBUG; then
        echo "DEBUG: Querying region: $REGION"
    fi

    AMI_INFO=$(aws ec2 describe-images \
        --region "$REGION" \
        --filters "Name=name,Values=$IMAGE_FILTER_LATEST" "Name=owner-id,Values=$OWNER_ID" \
        --query "Images[].[Name,ImageId]" \
        --output text)

    if [[ -n "$AMI_INFO" ]]; then
        while read -r NAME AMI_ID; do
            echo "$NAME"
            echo "  $REGION: $AMI_ID"
            REGION_LIST+=("$REGION")
            AMI_MAP+="$REGION: $AMI_ID"$'\n'
        done <<< "$AMI_INFO"
    fi
done

# Step 4: Generate YAML
YAML_OUTPUT="aws_region_choices:\n"
for REGION in "${REGION_LIST[@]}"; do
    YAML_OUTPUT+="  - $REGION\n"
done
YAML_OUTPUT+="ami_map:\n$AMI_MAP"

echo -e "\nGenerated YAML:\n$YAML_OUTPUT"
