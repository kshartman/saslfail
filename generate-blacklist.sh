#!/bin/bash
# Generate blacklist of repeat offenders from saslfail ban database
# Outputs sorted IP list or CSV with strike breakdown

BAN_DB="/var/lib/saslfail/bans.db"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate a blacklist of IPs that have been banned multiple times.

Options:
  --threshold N   Minimum total bans to include (default: 10)
  --show          Output CSV: ip,total,strike3,strike2,strike1 (sorted by total desc)
  -h, --help      Show this help message

Examples:
  $(basename "$0")                    # IPs with 10+ bans, sorted by IP
  $(basename "$0") --threshold 5      # IPs with 5+ bans
  $(basename "$0") --show             # CSV with strike breakdown
  $(basename "$0") --show --threshold 20  # CSV for 20+ ban IPs
EOF
    exit 0
}

# Defaults
THRESHOLD=10
SHOW_CSV=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold)
            if [[ -z "$2" || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "Error: --threshold requires a positive integer" >&2
                exit 1
            fi
            THRESHOLD="$2"
            shift 2
            ;;
        --show)
            SHOW_CSV=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

# Check database exists
if [[ ! -f "$BAN_DB" ]]; then
    echo "Error: Ban database not found: $BAN_DB" >&2
    exit 1
fi

if $SHOW_CSV; then
    # Output CSV with strike breakdown, sorted by total descending
    echo "ip,total,strike3,strike2,strike1"

    awk -F'|' '
    NR > 1 && $4 == "ban" {
        ip = $2
        strike = $5
        total[ip]++
        if (strike == 3) s3[ip]++
        else if (strike == 2) s2[ip]++
        else if (strike == 1) s1[ip]++
    }
    END {
        for (ip in total) {
            if (total[ip] >= '"$THRESHOLD"') {
                printf "%s,%d,%d,%d,%d\n", ip, total[ip], s3[ip]+0, s2[ip]+0, s1[ip]+0
            }
        }
    }
    ' "$BAN_DB" | sort -t',' -k2 -rn
else
    # Output sorted IP list only
    awk -F'|' '
    NR > 1 && $4 == "ban" {
        total[$2]++
    }
    END {
        for (ip in total) {
            if (total[ip] >= '"$THRESHOLD"') {
                print ip
            }
        }
    }
    ' "$BAN_DB" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
fi
