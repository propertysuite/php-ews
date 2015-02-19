<?php
/**
 * Contains EWSType_ArrayOfEmailAddressesType.
 */

/**
 * Specifies an array of all email addresses of an associated persona.
 *
 * @package php-ews\Type
 */
class EWSType_ArrayOfEmailAddressesType extends EWSType
{
    /**
     * Represents a fully resolved e-mail address.
     *
     * @since Exchange 2010
     *
     * @var \jamesiarmes\PhpEws\Type\EmailAddressType
     */
    public $Address;
}
