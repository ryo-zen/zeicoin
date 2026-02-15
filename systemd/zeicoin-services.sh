#!/bin/bash

# ZeiCoin Services Management Script
# Usage: zeicoin-services [start|stop|restart|status|logs]

set -e

SERVICES=(
    "zeicoin-mining.service"
    "zeicoin-transaction-api.service"
    "zeicoin-indexer.timer"
    "zeicoin-error-monitor.service"
)

ZEICOIN_HOME="${ZEICOIN_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ZEICOIN_CLI="$ZEICOIN_HOME/zig-out/bin/zeicoin"

is_port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":${port} "
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tuln 2>/dev/null | grep -q ":${port} "
    else
        return 1
    fi
}

case "$1" in
    start)
        echo "🚀 Starting ZeiCoin services..."
        sudo systemctl daemon-reload
        sudo systemctl start zeicoin.target
        echo "✅ All services started"
        ;;

    stop)
        echo "🛑 Stopping ZeiCoin services..."
        # Stop individual services first (target Wants= doesn't propagate stops)
        for service in "${SERVICES[@]}"; do
            sudo systemctl stop "$service" 2>/dev/null || true
        done
        sudo systemctl stop zeicoin.target 2>/dev/null || true
        echo "✅ All services stopped"
        ;;

    restart)
        echo "🔄 Restarting ZeiCoin services..."
        sudo systemctl daemon-reload
        for service in "${SERVICES[@]}"; do
            sudo systemctl restart "$service" 2>/dev/null || true
        done
        echo "✅ All services restarted"
        ;;

    status)
        echo "📊 ZeiCoin Services Status:"
        echo "================================"
        for service in "${SERVICES[@]}"; do
            echo -n "$service: "
            STATUS=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            if [ "$STATUS" = "active" ]; then
                echo "✅ Active"
            elif [ "$STATUS" = "activating" ]; then
                echo "🔄 Starting..."
            else
                echo "❌ Inactive"
            fi
        done
        echo ""
        echo "📈 Running Processes:"
        echo "================================"

        # Check zen_server
        echo -n "zen_server: "
        if pgrep -f zen_server > /dev/null; then
            PID=$(pgrep -f zen_server)
            echo "✅ Running (PID: $PID)"
        else
            echo "❌ Not running"
        fi

        # Check transaction_api
        echo -n "transaction_api: "
        if pgrep -f transaction_api > /dev/null; then
            PID=$(pgrep -f transaction_api)
            echo "✅ Running (PID: $PID)"
        else
            echo "❌ Not running"
        fi

        # Check indexer (may not be running if timer-based)
        echo -n "zeicoin_indexer: "
        if pgrep -f zeicoin_indexer > /dev/null; then
            PID=$(pgrep -f zeicoin_indexer)
            echo "🔄 Running (PID: $PID)"
        else
            echo "⏸️  Idle (timer-based, runs every 30s)"
        fi

        echo ""
        echo "⛏️ Mining Status:"
        echo "================================"
        if pgrep -f zen_server > /dev/null && pgrep -f "zen_server.*--mine" > /dev/null; then
            # Get miner name from process args
            MINER_NAME=$(pgrep -a -f "zen_server.*--mine" | grep -o -- '--mine [^ ]*' | cut -d' ' -f2 | head -1)
            echo "Mining: ✅ Active"
            echo "Miner: $MINER_NAME"
        else
            echo "Mining: ❌ Inactive"
        fi

        echo ""
        echo "🌐 Network Ports:"
        echo "================================"
        echo -n "P2P (10801): "
        is_port_listening 10801 && echo "✅ Listening" || echo "❌ Not listening"
        echo -n "Client API (10802): "
        is_port_listening 10802 && echo "✅ Listening" || echo "❌ Not listening"
        echo -n "RPC (10803): "
        is_port_listening 10803 && echo "✅ Listening" || echo "❌ Not listening"
        echo -n "Transaction API (8080): "
        is_port_listening 8080 && echo "✅ Listening" || echo "❌ Not listening"

        echo ""
        echo "🔗 API Health Checks:"
        echo "================================"

        # Check Transaction API
        echo -n "Transaction API (http://127.0.0.1:8080): "
        if curl -s --max-time 2 http://127.0.0.1:8080/api/nonce/tzei1alice123456789 > /dev/null 2>&1; then
            echo "✅ Healthy"
        else
            echo "❌ Not responding"
        fi

        # Check RPC
        echo -n "RPC Server (127.0.0.1:10803): "
        if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/10803" 2>/dev/null; then
            echo "✅ Reachable"
        else
            echo "❌ Not reachable"
        fi

        # Check blockchain height
        echo ""
        echo "⛓️  Blockchain Info:"
        echo "================================"
        if [ -x "$ZEICOIN_CLI" ]; then
            ZEICOIN_SERVER=127.0.0.1 timeout 3 "$ZEICOIN_CLI" status 2>/dev/null | grep -E "Height|Peers|Mempool" || echo "Unable to fetch blockchain status"
        else
            echo "CLI not available at $ZEICOIN_CLI"
        fi
        ;;

    logs)
        JOURNAL_UNITS=()
        if [ "$2" == "mining" ]; then
            JOURNAL_UNITS=(-u zeicoin-mining)
        elif [ "$2" == "api" ]; then
            JOURNAL_UNITS=(-u zeicoin-transaction-api)
        elif [ "$2" == "indexer" ]; then
            JOURNAL_UNITS=(-u zeicoin-indexer)
        elif [ "$2" == "monitor" ]; then
            JOURNAL_UNITS=(-u zeicoin-error-monitor)
        else
            JOURNAL_UNITS=(-u zeicoin-mining -u zeicoin-transaction-api -u zeicoin-indexer -u zeicoin-error-monitor)
        fi

        echo "📜 ZeiCoin Service Logs (Ctrl+C to exit):"
        echo "================================"
        sudo journalctl "${JOURNAL_UNITS[@]}" -f
        ;;

    enable)
        echo "🔧 Enabling ZeiCoin services to start on boot..."
        sudo systemctl daemon-reload
        sudo systemctl enable zeicoin.target
        for service in "${SERVICES[@]}"; do
            sudo systemctl enable "$service"
        done
        echo "✅ Services enabled for automatic startup"
        ;;

    disable)
        echo "🔧 Disabling automatic startup..."
        for service in "${SERVICES[@]}"; do
            sudo systemctl disable "$service" 2>/dev/null || true
        done
        sudo systemctl disable zeicoin.target 2>/dev/null || true
        echo "✅ Automatic startup disabled"
        ;;

    *)
        echo "ZeiCoin Services Manager"
        echo "Usage: $0 {start|stop|restart|status|logs [service]|enable|disable}"
        echo ""
        echo "Commands:"
        echo "  start           - Start all ZeiCoin services"
        echo "  stop            - Stop all ZeiCoin services"
        echo "  restart         - Restart all services"
        echo "  status          - Show comprehensive service status"
        echo "  logs [service]  - Follow service logs (mining|api|indexer|monitor|all)"
        echo "  enable          - Enable automatic startup on boot"
        echo "  disable         - Disable automatic startup"
        echo ""
        echo "Current Services:"
        echo "  • zeicoin-mining.service       - Blockchain server with mining"
        echo "  • zeicoin-transaction-api      - HTTP REST API (port 8080)"
        echo "  • zeicoin-indexer.timer        - PostgreSQL indexer (every 30s)"
        echo "  • zeicoin-error-monitor.service - Journal error monitor"
        exit 1
        ;;
esac
