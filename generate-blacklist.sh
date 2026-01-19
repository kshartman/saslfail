#!/bin/bash
# Generate blacklist of repeat offenders from saslfail ban database
# Outputs sorted IP list, CSV, or Markdown with strike breakdown

BAN_DB="/var/lib/saslfail/bans.db"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate a blacklist of IPs that have been banned multiple times.

Options:
  --threshold N       Minimum total bans to include (default: 10)
  --format [TYPE]     Output format: list, csv, md (default: csv if flag present, list if absent)
  -h, --help          Show this help message

Output Formats:
  list    Plain IP list sorted numerically (for ipset/firewall)
  csv     CSV with ip,total,strike3,strike2,strike1 (sorted by total desc)
  md      Markdown table with strike breakdown (sorted by total desc)

Examples:
  $(basename "$0")                        # Plain IP list with 10+ bans
  $(basename "$0") --threshold 5          # Plain IP list with 5+ bans
  $(basename "$0") --format               # CSV output (default when --format used)
  $(basename "$0") --format csv           # CSV output (explicit)
  $(basename "$0") --format md            # Markdown table
  $(basename "$0") --format list          # Same as no --format flag
EOF
    exit 0
}

# Defaults
THRESHOLD=10
FORMAT="list"

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
        --format)
            # Check if next arg is a format type or another flag/empty
            if [[ -z "$2" || "$2" == --* ]]; then
                FORMAT="csv"
                shift
            else
                case "$2" in
                    list|csv|md)
                        FORMAT="$2"
                        shift 2
                        ;;
                    *)
                        echo "Error: --format must be list, csv, or md" >&2
                        exit 1
                        ;;
                esac
            fi
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

case "$FORMAT" in
    list)
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
        ;;
    csv)
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
        ;;
    md)
        # Output Markdown table with strike breakdown, sorted by total descending
        echo "| IP | Total | Strike 3 | Strike 2 | Strike 1 |"
        echo "|-----|-------|----------|----------|----------|"
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
        ' "$BAN_DB" | sort -t',' -k2 -rn | awk -F',' '{printf "| %s | %d | %d | %d | %d |\n", $1, $2, $3, $4, $5}'
        ;;
esac
