jQuery(document).ready(function() {  
    $("form[name='employee']").validate({
    errorClass: "my-error-class", //for error colors
    // Specify validation rules
    rules: {
    // The key name on the left side is the name attribute
    // of an input field. Validation rules are defined
    // on the right side
    company_name: {
        required : true
    },
    employee_name: {
        required : true
    },
    phone_number:{
        required : true,
        maxlength : 10,
    },
    note: {
        required : true
    },
    designation: {
        required : true
    },
    employee_email: {
        required : true,
        email: true
    },
    
        
    },
    // Specify validation error messages
    messages: {
        company_name: "This field is required",
        employee_name: "This field is required",
        phone_number :{
            required : "this field is required",
            maxlength : "only 10 digit number is allowed"
        },
        note: "This field is required",
        designation: "You must assign a designation to the employee",
        employee_email: "Enter correct email",
        
    },
    // Make sure the form is submitted to the destination defined
    // in the "action" attribute of the form when valid
    submitHandler: function(form) {
    form.submit();
    toastr.success('User Created Successfully')
    }
})
});