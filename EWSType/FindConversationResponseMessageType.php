<?php
/**
 * Contains EWSType_FindConversationResponseMessageType.
 */

/**
 * Defines a response to a FindConversation Operation request.
 *
 * @package php-ews\Types
 *
 * @todo Extend EWSType_ResponseMessageType.
 */
class EWSType_FindConversationResponseMessageType extends EWSType
{
    /**
     * Contains an array of conversations.
     *
     * @since Exchange 2010 SP1
     *
     * @var EWSType_ArrayOfConversationsType
     */
    public $Conversations;

    /**
     * Currently unused and reserved for future use.
     *
     * This element contains a value of 0.
     *
     * @since Exchange 2010 SP1
     *
     * @var integer
     */
    public $DescriptiveLinkKey;

    /**
     * Provides a text description of the status of the response.
     *
     * @since Exchange 2010 SP1
     *
     * @var string
     */
    public $MessageText;

    /**
     * Provides additional error response information.
     *
     * @since Exchange 2010 SP1
     *
     * @var string
     *
     * @todo Determine if we can use SimpleXML or DOMDocument here.
     */
    public $MessageXml;

    /**
     * Describes the status of the response.
     *
     * @since Exchange 2010 SP1
     *
     * @var \jamesiarmes\PhpEws\Enumeration\ResponseClassType
     */
    public $ResponseClass;

    /**
     * Provides an error code that identifies the specific error that the
     * request encountered.
     *
     * @since Exchange 2010 SP1
     *
     * @var \jamesiarmes\PhpEws\Enumeration\ResponseCodeType
     */
    public $ResponseCode;
}
