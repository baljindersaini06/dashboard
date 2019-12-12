jQuery(document).ready(function() { 
$("form[name='password']").validate({
    errorClass: "my-error-class",
    // Specify validation rules
    rules: {
    // The key name on the left side is the name attribute
    // of an input field. Validation rules are defined
    // on the right side
    old_password: {
        required : true,
        remote : {url: "/test", async:false}
    },
    new_password1:{
        required : true,
        regex: /^(?=.*\d)(?=.+[A-Za-z])[0-9A-Za-z!@#$%]{8,20}$/
    },
    new_password2: {
        required : true,
        equalTo: "#new_password1"
    },
    },
    // Specify validation error messages
    messages: {
    old_password: {
        required : "Please enter your Current password",
        remote : "Please enter your corret password",
    },
    new_password1: {
        required : "Please enter your New Password",
        minlength: "Your password must be at least 8 characters long",
        //pwcheck: "The password does not match the criteria!",
    },
    new_password2: {
        required : "Please Confirm your Password",
        equalTo : "Enter Confirm password same as Password",
    }
    },
    // Make sure the form is submitted to the destination defined
    // in the "action" attribute of the form when valid
    submitHandler: function(form) {
    form.submit();
    toastr.success('Password Changed Successfully')
    }
});
//     $.validator.addMethod("pwcheck",
//                             function(value, element) {
//                                 return /^[A-Za-z0-9\d=!\-@._*]+$/.test(value);
//                         });
jQuery.validator.addMethod(
    "regex",
    function(value, element, regexp) {
        return regexp.test(value);
        // var re = new RegExp(regexp);
        // console.log(value);
        // console.log(regexp)

        // var re = /^\w+([-+.'][^\s]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
        // var emailFormat = re.test('sample123@gmail.com');

        // if (emailFormat) {
        //     console.log('Great, you entered an E-Mail-address');
        // }else{
        //     console.log("no")
        // }
        // console.log(re)
        // return this.optional(element) || re.test(value);
        // return re.test(value);
    },
    "Please check your Password and input one capital alphabet, small alphabet, numeric and special character ."
);
// $.validator.addMethod('regex', function(value, element, param) {
//     return this.optional(element) ||
//         value.match(typeof param == 'string' ? new RegExp(param) : param);
// },
// 'Please enter a value in the correct format.');
});

