document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refresh-btn');
    const logsBody = document.getElementById('logs-body');
    const modal = document.getElementById('log-modal');
    const closeBtn = document.querySelector('.close-btn');
    const modalBody = document.getElementById('modal-body');
    
    let chartInstance = null;
    let currentLogs = [];

    const fetchStats = async () => {
        try {
            const res = await fetch('/admin/stats');
            const data = await res.json();
            document.getElementById('total-val').textContent = data.total || 0;
            const maxVal = data.anomaly_max !== null ? parseFloat(data.anomaly_max).toFixed(4) : '0.00';
            document.getElementById('max-anomaly-val').textContent = maxVal;
        } catch (e) {
            console.error('Error fetching stats:', e);
        }
    };

    const renderChart = (logs) => {
        const ctx = document.getElementById('anomalyChart').getContext('2d');
        
        // Reverse for chronological order
        const chronoLogs = [...logs].reverse();
        const labels = chronoLogs.map(l => new Date(l.ts * 1000).toLocaleTimeString());
        const dataPoints = chronoLogs.map(l => l.anomaly_score);

        if (chartInstance) {
            chartInstance.destroy();
        }

        chartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Anomaly Score',
                    data: dataPoints,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#94a3b8' }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    };

    const getScoreClass = (score) => {
        if (score > 0.7) return 'score-high';
        if (score > 0.4) return 'score-med';
        return 'score-low';
    };

    const showDetails = (id) => {
        const log = currentLogs.find(l => l.id === id);
        if (!log) return;
        
        const dateStr = new Date(log.ts * 1000).toLocaleString();
        modalBody.innerHTML = `
            <p><strong>Time:</strong> ${dateStr}</p>
            <p><strong>IP:</strong> ${log.ip}</p>
            <p><strong>Method/Path:</strong> ${log.method} ${log.path}</p>
            <p><strong>User Agent:</strong> ${log.ua}</p>
            <p><strong>Content Length:</strong> ${log.content_length}</p>
            <p><strong>Anomaly Score:</strong> <span class="score-badge ${getScoreClass(log.anomaly_score)}">${parseFloat(log.anomaly_score).toFixed(4)}</span></p>
            <p><strong>Body Sample:</strong></p>
            <pre>${log.body_sample || '(empty)'}</pre>
        `;
        modal.classList.remove('hidden');
    };

    // Expose globally for inline onclick
    window.showDetails = showDetails;

    const renderLogs = (logs) => {
        currentLogs = logs;
        logsBody.innerHTML = '';
        logs.forEach(log => {
            const tr = document.createElement('tr');
            const dateStr = new Date(log.ts * 1000).toLocaleTimeString();
            const scoreClass = getScoreClass(log.anomaly_score);
            const scoreStr = parseFloat(log.anomaly_score).toFixed(4);
            
            tr.innerHTML = `
                <td>${dateStr}</td>
                <td>${log.ip}</td>
                <td>${log.method}</td>
                <td>${log.path}</td>
                <td><span class="score-badge ${scoreClass}">${scoreStr}</span></td>
                <td><button class="action-btn" onclick="showDetails(${log.id})">Details</button></td>
            `;
            logsBody.appendChild(tr);
        });
    };

    const fetchLogs = async () => {
        try {
            const res = await fetch('/admin/logs?limit=50');
            const data = await res.json();
            renderLogs(data.rows);
            renderChart(data.rows);
        } catch (e) {
            console.error('Error fetching logs:', e);
        }
    };

    const refreshAll = () => {
        fetchStats();
        fetchLogs();
    };

    refreshBtn.addEventListener('click', refreshAll);
    
    closeBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
    });

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.classList.add('hidden');
    });

    // Initial load
    refreshAll();
    
    // Auto refresh every 10s
    setInterval(refreshAll, 10000);
});
