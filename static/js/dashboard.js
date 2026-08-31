document.addEventListener("DOMContentLoaded", function () {

    /*
    =========================================================
    FIREWALL LOG ANALYZER
    Project 8 — Network Defense Dashboard
    =========================================================
    */

    if (typeof Chart === "undefined") {
        console.error("Chart.js could not be loaded.");
        return;
    }


    // =======================================================
    // CHART.JS DEFAULTS
    // =======================================================

    Chart.defaults.font.family =
        '"Segoe UI", Arial, sans-serif';

    Chart.defaults.font.size = 10;

    Chart.defaults.color = "#64748b";


    // =======================================================
    // FLASK DATA
    // =======================================================

    const data =
        typeof chartData !== "undefined"
            ? chartData
            : {};

    console.log("Firewall dashboard data:", data);


    // =======================================================
    // DATA NORMALIZATION
    // Handles both:
    //
    // {
    //     TCP: 14,
    //     UDP: 1
    // }
    //
    // and:
    //
    // {
    //     labels: ["TCP", "UDP"],
    //     values: [14, 1]
    // }
    // =======================================================

    function normalizeChartData(source) {

        if (!source) {
            return {
                labels: [],
                values: []
            };
        }


        // Format:
        // {labels: [...], values: [...]}

        if (
            !Array.isArray(source) &&
            Array.isArray(source.labels) &&
            Array.isArray(source.values)
        ) {

            return {
                labels: source.labels,
                values: source.values
            };

        }


        // Format:
        // {labels: [...], data: [...]}

        if (
            !Array.isArray(source) &&
            Array.isArray(source.labels) &&
            Array.isArray(source.data)
        ) {

            return {
                labels: source.labels,
                values: source.data
            };

        }


        // Format:
        // {TCP: 14, UDP: 1}

        if (
            !Array.isArray(source) &&
            typeof source === "object"
        ) {

            return {
                labels: Object.keys(source),
                values: Object.values(source)
            };

        }


        // Format:
        // [["TCP", 14], ["UDP", 1]]

        if (Array.isArray(source)) {

            if (
                source.length > 0 &&
                Array.isArray(source[0])
            ) {

                return {
                    labels: source.map(
                        item => item[0]
                    ),

                    values: source.map(
                        item => item[1]
                    )
                };

            }

        }


        return {
            labels: [],
            values: []
        };

    }


    // =======================================================
    // FIND DATA
    // =======================================================

    function findData(...keys) {

        for (const key of keys) {

            if (
                data[key] !== undefined &&
                data[key] !== null
            ) {

                return data[key];

            }

        }

        return {};
    }


    // =======================================================
    // CREATE CHART
    // =======================================================

    function createChart(canvasId, config) {

        const canvas =
            document.getElementById(canvasId);

        if (!canvas) {

            console.warn(
                `Canvas not found: ${canvasId}`
            );

            return null;
        }


        return new Chart(canvas, config);

    }


    // =======================================================
    // 1. TRAFFIC DECISIONS
    // =======================================================

    const actions =
        normalizeChartData(
            findData(
                "actions",
                "action_counts",
                "traffic_actions"
            )
        );


    console.log(
        "Actions:",
        actions
    );


    createChart(
        "actionsChart",
        {

            type: "doughnut",

            data: {

                labels: actions.labels,

                datasets: [
                    {
                        data: actions.values,

                        borderWidth: 0,

                        hoverOffset: 7
                    }
                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                cutout: "68%",

                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {

                            usePointStyle: true,

                            pointStyle: "circle",

                            padding: 14,

                            font: {
                                size: 9
                            }

                        }

                    }

                }

            }

        }
    );


    // =======================================================
    // 2. PROTOCOL DISTRIBUTION
    // =======================================================

    const protocols =
        normalizeChartData(
            findData(
                "protocols",
                "protocol_counts",
                "protocol_distribution"
            )
        );


    console.log(
        "Protocols:",
        protocols
    );


    createChart(
        "protocolChart",
        {

            type: "doughnut",

            data: {

                labels: protocols.labels,

                datasets: [
                    {
                        data: protocols.values,

                        borderWidth: 0,

                        hoverOffset: 7
                    }
                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                cutout: "68%",

                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {

                            usePointStyle: true,

                            pointStyle: "circle",

                            padding: 14,

                            font: {
                                size: 9
                            }

                        }

                    },

                    tooltip: {

                        callbacks: {

                            label: function (context) {

                                return (
                                    " " +
                                    context.label +
                                    ": " +
                                    context.raw
                                );

                            }

                        }

                    }

                }

            }

        }
    );


    // =======================================================
    // 3. TOP SOURCE IPs
    // =======================================================

    const sourceIPs =
        normalizeChartData(
            findData(
                "source_ips",
                "top_source_ips",
                "sources"
            )
        );


    console.log(
        "Source IPs:",
        sourceIPs
    );


    createChart(
        "sourceIpChart",
        {

            type: "bar",

            data: {

                labels: sourceIPs.labels,

                datasets: [
                    {

                        label: "Events",

                        data: sourceIPs.values,

                        borderRadius: 4,

                        borderSkipped: false

                    }
                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                indexAxis: "y",

                scales: {

                    x: {

                        beginAtZero: true,

                        ticks: {

                            precision: 0,

                            font: {
                                size: 9
                            }

                        }

                    },

                    y: {

                        ticks: {

                            font: {
                                size: 9
                            }

                        },

                        grid: {
                            display: false
                        }

                    }

                },

                plugins: {

                    legend: {
                        display: false
                    },

                    tooltip: {

                        callbacks: {

                            label: function (context) {

                                return (
                                    " Events: " +
                                    context.raw
                                );

                            }

                        }

                    }

                }

            }

        }
    );


    // =======================================================
    // 4. DESTINATION PORTS
    // =======================================================

    const ports =
        normalizeChartData(
            findData(
                "destination_ports",
                "ports",
                "top_destination_ports"
            )
        );


    console.log(
        "Destination ports:",
        ports
    );


    createChart(
        "portChart",
        {

            type: "bar",

            data: {

                labels: ports.labels,

                datasets: [
                    {

                        label: "Connections",

                        data: ports.values,

                        borderRadius: 4,

                        borderSkipped: false

                    }
                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                scales: {

                    x: {

                        ticks: {

                            font: {
                                size: 9
                            }

                        },

                        grid: {
                            display: false
                        }

                    },

                    y: {

                        beginAtZero: true,

                        ticks: {

                            precision: 0,

                            font: {
                                size: 9
                            }

                        }

                    }

                },

                plugins: {

                    legend: {
                        display: false
                    },

                    tooltip: {

                        callbacks: {

                            title: function (context) {

                                return (
                                    "Port " +
                                    context[0].label
                                );

                            },

                            label: function (context) {

                                return (
                                    " Connections: " +
                                    context.raw
                                );

                            }

                        }

                    }

                }

            }

        }
    );


    // =======================================================
    // EVENT SEARCH
    // =======================================================

    const searchInput =
        document.getElementById("eventSearch");

    const actionFilter =
        document.getElementById("actionFilter");

    const protocolFilter =
        document.getElementById("protocolFilter");

    const table =
        document.getElementById("eventsTable");

    const noResults =
        document.getElementById("noSearchResults");


    function filterEvents() {

        if (!table) {
            return;
        }


        const rows =
            table.querySelectorAll(
                "tbody tr"
            );


        const searchTerm =
            searchInput
                ? searchInput.value
                    .trim()
                    .toLowerCase()
                : "";


        const selectedAction =
            actionFilter
                ? actionFilter.value
                : "ALL";


        const selectedProtocol =
            protocolFilter
                ? protocolFilter.value
                : "ALL";


        let visibleRows = 0;


        rows.forEach(function (row) {

            const rowText =
                row.textContent
                    .toLowerCase();


            const actionCell =
                row.cells[7]
                    ? row.cells[7]
                        .textContent
                        .trim()
                        .toUpperCase()
                    : "";


            const protocolCell =
                row.cells[6]
                    ? row.cells[6]
                        .textContent
                        .trim()
                        .toUpperCase()
                    : "";


            const matchesSearch =
                rowText.includes(
                    searchTerm
                );


            const matchesAction =
                selectedAction === "ALL" ||
                actionCell === selectedAction;


            const matchesProtocol =
                selectedProtocol === "ALL" ||
                protocolCell === selectedProtocol;


            const visible =
                matchesSearch &&
                matchesAction &&
                matchesProtocol;


            row.style.display =
                visible
                    ? ""
                    : "none";


            if (visible) {
                visibleRows++;
            }

        });


        if (noResults) {

            noResults.style.display =
                visibleRows === 0
                    ? "block"
                    : "none";

        }

    }


    if (searchInput) {

        searchInput.addEventListener(
            "input",
            filterEvents
        );

    }


    if (actionFilter) {

        actionFilter.addEventListener(
            "change",
            filterEvents
        );

    }


    if (protocolFilter) {

        protocolFilter.addEventListener(
            "change",
            filterEvents
        );

    }


    // =======================================================
    // SIDEBAR NAVIGATION
    // =======================================================

    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );


    navItems.forEach(function (item) {

        item.addEventListener(
            "click",
            function () {

                navItems.forEach(
                    function (nav) {

                        nav.classList.remove(
                            "active"
                        );

                    }
                );


                item.classList.add(
                    "active"
                );

            }
        );

    });


    // =======================================================
    // SECTION OBSERVER
    // =======================================================

    const sections =
        document.querySelectorAll(
            ".dashboard-section, .report-actions"
        );


    if ("IntersectionObserver" in window) {

        const observer =
            new IntersectionObserver(
                function (entries) {

                    entries.forEach(
                        function (entry) {

                            if (
                                !entry.isIntersecting
                            ) {
                                return;
                            }


                            const id =
                                entry.target.id;


                            navItems.forEach(
                                function (item) {

                                    const href =
                                        item.getAttribute(
                                            "href"
                                        );


                                    if (
                                        href ===
                                        "#" + id
                                    ) {

                                        navItems.forEach(
                                            function (nav) {

                                                nav.classList.remove(
                                                    "active"
                                                );

                                            }
                                        );


                                        item.classList.add(
                                            "active"
                                        );

                                    }

                                }
                            );

                        }
                    );

                },
                {
                    threshold: 0.35
                }
            );


        sections.forEach(
            function (section) {

                observer.observe(
                    section
                );

            }
        );

    }


    // =======================================================
    // TABLE ROW SELECTION
    // =======================================================

    if (table) {

        const rows =
            table.querySelectorAll(
                "tbody tr"
            );


        rows.forEach(
            function (row) {

                row.addEventListener(
                    "click",
                    function () {

                        rows.forEach(
                            function (r) {

                                r.classList.remove(
                                    "selected-row"
                                );

                            }
                        );


                        row.classList.add(
                            "selected-row"
                        );

                    }
                );

            }
        );

    }


    // =======================================================
    // INITIALIZATION
    // =======================================================

    console.log(
        "Firewall Log Analyzer dashboard initialized successfully."
    );

});