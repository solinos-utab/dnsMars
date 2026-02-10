#!/bin/bash
#
# DNS Performance Testing & Load Generation Script
# For 100Gbps Capacity Validation
# PT MARS DATA TELEKOMUNIKASI
#

set -e

COLORS='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

log_info() {
    echo -e "${BLUE}[INFO]${COLORS} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${COLORS} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${COLORS} $1"
}

log_error() {
    echo -e "${RED}[✗]${COLORS} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    REQUIRED_TOOLS=("dig" "timeout" "awk" "bc")
    MISSING=0
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool not found"
            MISSING=$((MISSING + 1))
        fi
    done
    
    # Optional but recommended
    if ! command -v dnsperf &> /dev/null; then
        log_warning "dnsperf not found. For better results run: apt-get install dnsperf"
    fi
    
    if [ $MISSING -gt 0 ]; then
        log_error "$MISSING required tools missing. Install dnsutils package."
        exit 1
    fi
    
    log_success "Dependencies check passed"
}

# Test 1: Basic Connectivity
test_connectivity() {
    log_info "Running Test 1: DNS Connectivity Check"
    
    TEST_DOMAINS=(
        "google.com"
        "example.com"
        "cloudflare.com"
        "quad9.net"
        "8.8.8.8"
    )
    
    local PASSED=0
    local FAILED=0
    
    for domain in "${TEST_DOMAINS[@]}"; do
        if dig +short "$domain" @127.0.0.1 &>/dev/null; then
            log_success "Query for $domain: OK"
            ((PASSED++))
        else
            log_error "Query for $domain: FAILED"
            ((FAILED++))
        fi
    done
    
    echo ""
    echo "Connectivity Test Results: $PASSED passed, $FAILED failed"
    echo ""
}

# Test 2: Response Time
test_response_time() {
    log_info "Running Test 2: Average Response Time (10 queries)"
    
    local TOTAL_TIME=0
    local QUERY_COUNT=0
    
    for i in {1..10}; do
        local START=$(date +%s%N)
        dig example.com @127.0.0.1 +short &>/dev/null
        local END=$(date +%s%N)
        
        local ELAPSED=$(( (END - START) / 1000000 ))  # Convert to ms
        TOTAL_TIME=$((TOTAL_TIME + ELAPSED))
        QUERY_COUNT=$((QUERY_COUNT + 1))
        
        echo "  Query $i: ${ELAPSED}ms"
    done
    
    local AVG=$((TOTAL_TIME / QUERY_COUNT))
    echo ""
    echo "Average Response Time: ${AVG}ms"
    
    if [ $AVG -lt 50 ]; then
        log_success "Response time is excellent (< 50ms)"
    elif [ $AVG -lt 100 ]; then
        log_success "Response time is good (< 100ms)"
    else
        log_warning "Response time is slow (> 100ms)"
    fi
    echo ""
}

# Test 3: Concurrent Queries
test_concurrent_queries() {
    log_info "Running Test 3: Concurrent Queries (100 parallel queries)"
    
    local CONCURRENT=100
    local START=$(date +%s)
    
    # Run 100 concurrent dig queries
    for i in $(seq 1 $CONCURRENT); do
        (dig example.com @127.0.0.1 +short &>/dev/null) &
    done
    
    # Wait for all to complete
    wait
    
    local END=$(date +%s)
    local DURATION=$((END - START))
    
    if [ $DURATION -eq 0 ]; then
        DURATION=1
    fi
    
    local QPS=$((CONCURRENT / DURATION))
    echo ""
    echo "Concurrent Test Results:"
    echo "  Total Queries: $CONCURRENT"
    echo "  Duration: ${DURATION}s"
    echo "  Estimated QPS: ~$((CONCURRENT * 1000 / (DURATION * 1000)))K QPS"
    echo ""
}

# Test 4: Cache Effectiveness
test_cache_effectiveness() {
    log_info "Running Test 4: Cache Effectiveness (repeated queries)"
    
    local DOMAIN="example.com"
    local ITERATIONS=100
    
    log_info "Flushing and testing with $ITERATIONS iterations..."
    
    # First query (cache miss)
    local START1=$(date +%s%N)
    dig "$DOMAIN" @127.0.0.1 +short &>/dev/null
    local END1=$(date +%s%N)
    local FIRST_QUERY_MS=$(( (END1 - START1) / 1000000 ))
    
    # Repeat queries (cache hits)
    local TOTAL_CACHED=0
    for i in $(seq 1 $ITERATIONS); do
        local START=$(date +%s%N)
        dig "$DOMAIN" @127.0.0.1 +short &>/dev/null
        local END=$(date +%s%N)
        TOTAL_CACHED=$((TOTAL_CACHED + (END - START)))
    done
    
    local AVG_CACHED=$(( TOTAL_CACHED / (ITERATIONS * 1000000) ))
    
    echo ""
    echo "Cache Effectiveness Results:"
    echo "  First Query (miss): ${FIRST_QUERY_MS}ms"
    echo "  Avg Cached Query: ${AVG_CACHED}ms"
    
    if [ $AVG_CACHED -lt $FIRST_QUERY_MS ]; then
        log_success "Cache is working! Speedup: $((FIRST_QUERY_MS / (AVG_CACHED + 1)))x"
    fi
    echo ""
}

# Test 5: Multiple A Records
test_multiple_records() {
    log_info "Running Test 5: Multiple Record Types Query"
    
    local DOMAIN="google.com"
    
    for QUERY_TYPE in A AAAA MX TXT NS SOA; do
        local START=$(date +%s%N)
        dig "$DOMAIN" @127.0.0.1 "$QUERY_TYPE" +short &>/dev/null
        local END=$(date +%s%N)
        
        local ELAPSED=$(( (END - START) / 1000000 ))
        echo "  $QUERY_TYPE query: ${ELAPSED}ms"
    done
    echo ""
}

# Test 6: Unbound Stats (if available)
test_unbound_stats() {
    log_info "Running Test 6: Unbound Cache Statistics"
    
    if command -v unbound-control &> /dev/null; then
        unbound-control stats 2>/dev/null | grep -E "num.*query|cache" | head -10 || {
            log_warning "Could not retrieve unbound stats (might need authentication)"
        }
    else
        log_warning "unbound-control not available"
    fi
    echo ""
}

# Stress Test: High Load
stress_test() {
    local TARGET_QPS=${1:-1000}
    
    log_info "Running STRESS TEST: Targeting $TARGET_QPS QPS for 60 seconds"
    log_warning "This will generate significant load. Monitor system resources!"
    
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Stress test cancelled"
        return
    fi
    
    local DOMAINS=(
        "google.com" "facebook.com" "youtube.com" "amazon.com"
        "twitter.com" "instagram.com" "github.com" "stackoverflow.com"
        "example.com" "test.com"
    )
    
    local QUERIES_SENT=0
    local QUERIES_SUCCESS=0
    local QUERIES_FAILED=0
    local START_TIME=$(date +%s)
    
    log_info "Starting stress test..."
    
    while true; do
        local CURRENT_TIME=$(date +%s)
        local ELAPSED=$((CURRENT_TIME - START_TIME))
        
        if [ $ELAPSED -ge 60 ]; then
            break
        fi
        
        # Calculate how many queries to send in this iteration
        local TARGET_QUERIES=$((TARGET_QPS / 10))  # 10 iterations per second
        
        for i in $(seq 1 $TARGET_QUERIES); do
            local RANDOM_DOMAIN=${DOMAINS[$((RANDOM % ${#DOMAINS[@]}))]}
            
            if dig "$RANDOM_DOMAIN" @127.0.0.1 +short &>/dev/null; then
                ((QUERIES_SUCCESS++))
            else
                ((QUERIES_FAILED++))
            fi
            ((QUERIES_SENT++))
        done
        
        # Print progress every 10 seconds
        if [ $((ELAPSED % 10)) -eq 0 ]; then
            local CURRENT_QPS=$((QUERIES_SENT / ELAPSED))
            echo "  $ELAPSED/60s: $QUERIES_SENT queries sent, ~${CURRENT_QPS} QPS actual"
        fi
        
        sleep 0.1
    done
    
    local TOTAL_ELAPSED=$(($(date +%s) - START_TIME))
    local ACTUAL_QPS=$((QUERIES_SENT / TOTAL_ELAPSED))
    local SUCCESS_RATE=$((QUERIES_SUCCESS * 100 / QUERIES_SENT))
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  STRESS TEST RESULTS (60 seconds)                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo "Target QPS:        $TARGET_QPS"
    echo "Actual QPS:        $ACTUAL_QPS"
    echo "Total Queries:     $QUERIES_SENT"
    echo "Successful:        $QUERIES_SUCCESS"
    echo "Failed:            $QUERIES_FAILED"
    echo "Success Rate:      $SUCCESS_RATE%"
    echo "Duration:          ${TOTAL_ELAPSED}s"
    echo ""
    
    if [ $SUCCESS_RATE -ge 99 ]; then
        log_success "Stress test passed with high success rate!"
    elif [ $SUCCESS_RATE -ge 95 ]; then
        log_success "Stress test passed with acceptable success rate"
    else
        log_error "High failure rate detected!"
    fi
    echo ""
}

# Generate comprehensive report
generate_test_report() {
    log_info "Generating comprehensive test report..."
    
    local REPORT_FILE="/home/dns/test_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  DNS PERFORMANCE TEST REPORT                               ║"
        echo "║  Generated: $(date)                           ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""
        
        echo "SYSTEM INFORMATION"
        echo "=================="
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "CPU Cores: $(nproc)"
        echo "RAM: $(free -h | grep Mem | awk '{print $2}')"
        echo ""
        
        echo "DNS SERVICES STATUS"
        echo "==================="
        echo "dnsmasq: $(systemctl is-active dnsmasq)"
        echo "unbound: $(systemctl is-active unbound)"
        echo ""
        
        echo "CONFIGURATION"
        echo "============="
        if [ -f /etc/dnsmasq.d/smartdns.conf ]; then
            echo "dnsmasq cache-size: $(grep cache-size /etc/dnsmasq.d/smartdns.conf | grep -v '^#' | head -1)"
        fi
        if [ -f /etc/unbound/conf.d/smartdns.conf ]; then
            echo "unbound threads: $(grep num-threads /etc/unbound/conf.d/smartdns.conf | grep -v '^#' | head -1)"
            echo "unbound ratelimit: $(grep ratelimit: /etc/unbound/conf.d/smartdns.conf | grep -v '^#' | head -1)"
        fi
        echo ""
        
    } | tee "$REPORT_FILE"
    
    log_success "Report saved to: $REPORT_FILE"
}

# Show menu
show_menu() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  DNS PERFORMANCE TEST SUITE                                ║"
    echo "║  PT MARS DATA TELEKOMUNIKASI                               ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Select test:"
    echo "  1) Quick Connectivity Test"
    echo "  2) Response Time Test"
    echo "  3) Concurrent Queries Test"
    echo "  4) Cache Effectiveness Test"
    echo "  5) Multiple Record Types Test"
    echo "  6) Unbound Statistics"
    echo "  7) Stress Test (1000 QPS)"
    echo "  8) Custom Stress Test"
    echo "  9) Run ALL Tests"
    echo "  10) Generate Report"
    echo "  0) Exit"
    echo ""
}

# ===== MAIN EXECUTION =====
if [ -z "$1" ]; then
    check_dependencies
    
    while true; do
        show_menu
        read -p "Select test [0-10]: " choice
        
        case $choice in
            1) test_connectivity ;;
            2) test_response_time ;;
            3) test_concurrent_queries ;;
            4) test_cache_effectiveness ;;
            5) test_multiple_records ;;
            6) test_unbound_stats ;;
            7) stress_test 1000 ;;
            8) 
                read -p "Enter target QPS [default 5000]: " custom_qps
                custom_qps=${custom_qps:-5000}
                stress_test "$custom_qps"
                ;;
            9)
                test_connectivity
                test_response_time
                test_concurrent_queries
                test_cache_effectiveness
                test_multiple_records
                test_unbound_stats
                stress_test 1000
                ;;
            10) generate_test_report ;;
            0) 
                log_info "Exiting..."
                exit 0
                ;;
            *) log_error "Invalid choice. Please select 0-10." ;;
        esac
        
        read -p "Press Enter to continue..."
    done
else
    check_dependencies
    
    case "$1" in
        connectivity) test_connectivity ;;
        response_time) test_response_time ;;
        concurrent) test_concurrent_queries ;;
        cache) test_cache_effectiveness ;;
        records) test_multiple_records ;;
        stats) test_unbound_stats ;;
        stress) stress_test "${2:-1000}" ;;
        all) 
            test_connectivity
            test_response_time
            test_concurrent_queries
            test_cache_effectiveness
            test_multiple_records
            test_unbound_stats
            ;;
        report) generate_test_report ;;
        *)
            echo "Usage: $0 [connectivity|response_time|concurrent|cache|records|stats|stress [QPS]|all|report]"
            exit 1
            ;;
    esac
fi

log_success "Tests completed!"
