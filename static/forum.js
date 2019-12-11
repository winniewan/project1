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

