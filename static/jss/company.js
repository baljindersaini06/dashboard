jQuery(document).ready(function() {
    $('form[id="form9"]').validate({
        errorClass: 'my-error-class',
        rules: {
            company_name: 'required',
            contact_number: {
                required : true,
                maxlength : 10,
            },
            description: 'required',
            company_website: 'required',
            company_logo: {

                extension: "jpg|jpeg|png|ico|bmp"
            },
            company_address: 'required',
            company_location: 'required',
            company_pincode: {
                required : true,
                maxlength : 5,
            }
        },
        messages: {
            company_name: 'This field is required',
            contact_number :{
                required : "this field is required",
                maxlength : "only 10 digit number is allowed"
            },
            description: 'This field is required',
            company_website: 'This field is required',
            company_logo: {
            extension:'Please upload file in these format only (jpg, jpeg, png, ico, bmp).'
            },
            company_address: 'This field is required',
            company_location: 'This field is required',
            company_pincode: {
                required: "This field is required",
                maxlength: "Pincode can only contains 5 digits"
              },
            
            
        },
        submitHandler: function(form) {
        form.submit();
        toastr.success('Company added successfully')

        }
    });
});

