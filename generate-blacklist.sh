#!/bin/bash
# Generate blacklist of repeat offenders from saslfail ban database
# Outputs sorted IP list, CSV, or Markdown with offense/strike breakdown
# Threshold is based on Strike 3 count (persistent attackers)

BAN_DB="/var/lib/saslfail/bans.db"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate a blacklist of IPs that have reached Strike 3 multiple times.

Options:
  --threshold N       Minimum Strike 3 bans to include (default: 2)
  --format [TYPE]     Output format: list, csv, md, doc (default: csv if flag present, list if absent)
  -h, --help          Show this help message

Output Formats:
  list    Plain IP list sorted numerically (for ipset/firewall)
  csv     CSV with ip,strike3,strike2,strike1,total (sorted by strike3 desc)
  md      Markdown table with strike breakdown (sorted by strike3 desc)
  doc     Full markdown document with header and table

Note: Each Strike 3 = 32-day ban. IPs reaching Strike 3 multiple times are persistent attackers.

Examples:
  $(basename "$0")                        # Plain IP list with 2+ Strike 3 bans
  $(basename "$0") --threshold 3          # IPs with 3+ Strike 3 bans
  $(basename "$0") --format               # CSV output (default when --format used)
  $(basename "$0") --format csv           # CSV output (explicit)
  $(basename "$0") --format md            # Markdown table
  $(basename "$0") --format doc           # Full markdown document
  $(basename "$0") --format list          # Same as no --format flag
EOF
    exit 0
}

# Defaults
THRESHOLD=2
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
                    list|csv|md|doc)
                        FORMAT="$2"
                        shift 2
                        ;;
                    *)
                        echo "Error: --format must be list, csv, md, or doc" >&2
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
        # Output sorted IP list only (filtered by Strike 3 count)
        awk -F'|' '
        NR > 1 && $4 == "ban" && $5 == 3 {
            s3[$2]++
        }
        END {
            for (ip in s3) {
                if (s3[ip] >= '"$THRESHOLD"') {
                    print ip
                }
            }
        }
        ' "$BAN_DB" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    csv)
        # Output CSV with strike breakdown, sorted by Strike 3 count descending
        echo "ip,strike3,strike2,strike1,total"
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
            for (ip in s3) {
                if (s3[ip] >= '"$THRESHOLD"') {
                    printf "%s,%d,%d,%d,%d\n", ip, s3[ip]+0, s2[ip]+0, s1[ip]+0, total[ip]
                }
            }
        }
        ' "$BAN_DB" | sort -t',' -k2 -rn
        ;;
    md)
        # Output Markdown table with strike breakdown, sorted by Strike 3 count descending
        echo "| IP | Strike 3 | Strike 2 | Strike 1 | Total |"
        echo "|-----|----------|----------|----------|-------|"
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
            for (ip in s3) {
                if (s3[ip] >= '"$THRESHOLD"') {
                    printf "%s,%d,%d,%d,%d\n", ip, s3[ip]+0, s2[ip]+0, s1[ip]+0, total[ip]
                }
            }
        }
        ' "$BAN_DB" | sort -t',' -k2 -rn | awk -F',' '{printf "| %s | %d | %d | %d | %d |\n", $1, $2, $3, $4, $5}'
        ;;
    doc)
        # Output full Markdown document with header and table
        ip_count=$(awk -F'|' '
        NR > 1 && $4 == "ban" && $5 == 3 { s3[$2]++ }
        END { count=0; for (ip in s3) if (s3[ip] >= '"$THRESHOLD"') count++; print count }
        ' "$BAN_DB")

        echo "# SASLFAIL Blacklist - Repeat Offenders"
        echo ""
        echo "**Generated:** $(date '+%Y-%m-%d')"
        echo "**Threshold:** ${THRESHOLD}+ Strike 3 bans"
        echo "**Total IPs:** ${ip_count}"
        echo ""
        echo "| IP | Strike 3 | Strike 2 | Strike 1 | Total |"
        echo "|-----|----------|----------|----------|-------|"
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
            for (ip in s3) {
                if (s3[ip] >= '"$THRESHOLD"') {
                    printf "%s,%d,%d,%d,%d\n", ip, s3[ip]+0, s2[ip]+0, s1[ip]+0, total[ip]
                }
            }
        }
        ' "$BAN_DB" | sort -t',' -k2 -rn | awk -F',' '{printf "| %s | %d | %d | %d | %d |\n", $1, $2, $3, $4, $5}'
        ;;
esac
