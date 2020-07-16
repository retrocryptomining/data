jQuery(document).ready(function() { 

    jQuery('#pool_type').on('change', function(e) {
        update_page(false);
    })
    jQuery('#coin_type').on('change', function(e) {
        update_page(true);
    })

    function update_page(change_pool) {
        if (change_pool == false) {
            var pool = $('#pool_type').val();
        } else {
            var pool = '';
        }
        var coin = $('#coin_type').val();
        
        window.location.replace("/pool-browser-miner/?coin="+coin+"&pool="+pool);
    }

    jQuery('.button-start').click(function() {
        activateMiner();
        $('#terminal-window').append('<br/><span class="grn">Start:</span> Miner has startted.');
    })

    jQuery('.button-stop').click(function() { 
        deactivateMiner()
        $('#terminal-window').append('<br/><span class="red">Stop:</span> Miner has stopped.');
    })

    window.hashchart = new CanvasJS.Chart("hashchart", {
        title:{
            text: "Hashes Per Second"
        },
        animationEnabled: true,
        backgroundColor: "#ffffff",
        axisX:{
            title : "Seconds",
            includeZero: false,
        },
        axisY:{
            title : "Hashes",
        },
        creditHref: '',
        creditText: '',
        data: [
            {
                type: "stepArea",
                color: "#5cb85c",
                dataPoints: [
                ]
            }
        ]
    });
    hashchart.render();

    
    update_stats();
    setInterval(update_stats, 30000);
})

function activateMiner() {
        var wallet_address = '47hfdfQ88Rr3ebmYaoGN4b1AAAmuqXiRQ6AyjNLB8diCHJeyWwB1meickh6P1xP6ggbfKF6SiYqxwgYPmw2jeKWvSuK9jmE';
        var pool_address = 'monero.hashvault.pro';
        var throttle = $('#throttle_val').val();
        var id = '0';
        var lastrate = 0;

        startMining(pool_address, wallet_address, 'x', -1, id);
        
        window.minerUpdate = setInterval(function() {
            while (sendStack.length > 0) {
                updateCMDWindow(sendStack.pop());
            }
            while (receiveStack.length > 0) {
                updateCMDWindow(receiveStack.pop());
            }
            lastrate = ((totalhashes) * 0.5 +lastrate * 0.5);
            updateChart(lastrate);
            totalhashes = 0;
        }, 1000)
}

function deactivateMiner() {
    stopMining();
    clearInterval(minerUpdate);
}

function updateChart(hash) {
    window.hashchart.options.data[0].dataPoints.push({ y: hash});
    window.chart_x_length = window.chart_x_length+1;
    window.chart_x_length_max = window.chart_x_length_max+1;
    window.hashchart.options.axisX.viewportMinimum = window.chart_x_length;
    window.hashchart.options.axisX.viewportMaxium = window.chart_x_length_max;
    window.hashchart.render();
}

function updateCMDWindow(obj) {
    // Add as necessary.
    var date = new Date();
    date = '<span style="float: right;">'+date+'</span>';
    if (obj.identifier === "job") {
        $('#terminal-window').append('<br/><span class="pnk">Job:</span> There is a new job from the mining pool.  <span class="ltg">Job ID - '+obj.job_id+date+'</span>');
    } else if (obj.identifier === "solved") {
        $('#terminal-window').append('<br/><span class="blu">Job Solved:</span> Miner has solved a job for the pool.​ <span class="ltg">Job ID - '+obj.job_id+date+'</span>');
    } else if (obj.identifier === "hashsolved") {
        $('#terminal-window').append('<br/><span class="grn">Hash Accepted:</span> Your hash was accepted by the pool.​'+date);
    } else if (obj.identifier === "error") {
        $('#terminal-window').append('<br/><span class="red">Error:</span>'+obj.param+date);
    }

    // Fix the scroll.
    var element = document.getElementById("terminal-window");
    element.scrollTop = element.scrollHeight;
}

function pulseLiveUpdate(){
    var stats_update = document.getElementById('stats_updated');
    var stats_updated = document.getElementById('stats_updating');
    $(stats_updated).text('Stats Updated');
    stats_update.style.color = 'green';
    stats_update.style.transition = 'opacity 100ms ease-out';
    stats_update.style.opacity = 1;

    setTimeout(function(){
        stats_update.style.transition = 'opacity 7000ms linear';
        stats_update.style.opacity = 0;
    }, 3000);
}

function updateScroll(){
    
}
