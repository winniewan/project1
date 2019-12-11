function up_vote(self) {
    var id = self.attr('id').split('_')[0];

    $.ajax({
        "url": "/up_vote/" + id,
        "type": "POST",
        "dataType": "text"
    }).done(function(response) {
        $("#" + id + "_votes").text(response);
    });

}

function down_vote(self) {
    var id = self.attr('id').split('_')[0];

    $.ajax({
        "url": "/down_vote/" + id,
        "type": "POST",
        "dataType": "text"
    }).done(function(response) {
        $("#" + id + "_votes").text(response);
    });
}

$(".up_arrow").each(function () {
        $(this).on('click', function () {
            up_vote($(this));
        })
    }
);

$(".down_arrow").each(function () {
        $(this).on('click', function () {
            down_vote($(this));
        })
    }
);

var loaded = 25;
var amountNextToLoad = 25;
var lock = false;

function isScrolledIntoView(elem)
{
    var docViewTop = $(window).scrollTop();
    var docViewBottom = docViewTop + $(window).height();

    var elemTop = $(elem).offset().top;
    var elemBottom = elemTop + $(elem).height();

    return ((elemBottom <= docViewBottom) && (elemTop >= docViewTop));
}

window.onscroll = function () {
    let $moretarget = $("#moretarget");

    if (!lock && $moretarget.length && isScrolledIntoView($moretarget)) {
        // ajax call get data from server and append to the div
        lock = true;

        $.ajax({
            "url": "/get_posts" + window.location.pathname,
            "type": "GET",
            "dataType": "text",
            "data": {
                "count": amountNextToLoad,
                "after": loaded
            },
            success: function (response) {
                $("#moretarget").replaceWith(response);
                loaded = loaded + amountNextToLoad;
                lock = false;
            }
        });
    }
}


